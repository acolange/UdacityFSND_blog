import os
import jinja2
import webapp2
import re
import hashlib
import string
import random
# import user
# import post
# import comment
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')

jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def valid_user(username):
    regex = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and regex.match(username)


def valid_pass(password):
    regex = re.compile(r"^.{3,20}$")
    return password and regex.match(password)


def valid_email(email):
    regex = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return not email or regex.match(email)


def make_salt():
    return ''.join(random.choice(string.lowercase) for i in range(5))


def user_logged_in(self):
    """Method for checking if a user is logged in via a cookie

    Takes an HTTP request and verifies the user cookie to check the user is
    logged in.  If a user is logged in the user data is returned.

    """
    user = None
    u = self.request.cookies.get('name')
    if u:
        u = u.split('|')
        if u[1] == hashlib.sha256(u[0] + 'blog').hexdigest():
            user = User.get_by_id(int(u[0]))
            # self.write(user)
            user.logged_in = True
            return user
    else:
        return user


class Handler(webapp2.RequestHandler):
    """

    Helper class to simplify common calls to the webapp2.RequestHandler.

    write() - Simplifies self.responst.out.write() to self.write()

    render_str() - Simplifies calling a jinja template

    render() - Calls write() on render_str() with a template and optional
    parameters to render the webpage.

    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class Post(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    submitter_id = db.IntegerProperty(required=True)
    submitter = db.StringProperty(required=True)
    likes = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    body = db.TextProperty(required=True)
    submitter_id = db.IntegerProperty(required=True)
    submitter = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)


class MainPage(Handler):
    """

    Class to handle rendering the blog's main page.

    """
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC LIMIT 10")
        user = user_logged_in(self)

        self.render("posts.html",
                    posts=posts,
                    user=user)


class NewEntry(Handler):
    """

    Class to handle the page for displaying a newly created post from the user.

    """
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        user = user_logged_in(self)
        user_id = None
        if user:
            user_id = user.key().id()
        comments = {}
        comments = db.GqlQuery("SELECT * FROM Comment "
                               "WHERE post_id = :id ORDER BY created DESC",
                               id=int(post_id))
        self.render("postpage.html",
                    user=user,
                    user_id=user_id,
                    post=post,
                    comments=comments)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        body = self.request.get("body")
        user = user_logged_in(self)
        user_id = None
        if user:
            user_id = user.key().id()

        comment = Comment(post_id=int(post_id),
                          body=body,
                          submitter_id=user_id,
                          submitter=user.name)
        comment.put()

        self.redirect("/" + str(post_id))
        # self.render("postpage.html",
        #             user=user,
        #             user_id=user_id,
        #             post=post,
        #             comments=comments)


class NewUser(Handler):
    """Handles the User signup page functions.

    Contains a GET request function that renders a signup form.
    Contains a POST request to submit and validate the user signup information.
    Validates a valid username, password, and email.   Stores the user into the
    database along with encrypted login information.

    Attributes:
        user: User information structure
        signup_error: Dictionary of errors that can occur during signup.

    """
    def get(self):
        user = user_logged_in(self)
        if not user:
            self.render("signup.html", user={})
        else:
            self.render("/")

    def post(self):
        # Initialize and fetch data from signup form
        signup_error = False
        params = {}
        email_valid = True
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        # Verify a valid username, email, password, and matching verfication.
        if not valid_email(email):
            signup_error = True
            params['email_error'] = "Invalid email"
        else:
            params['email'] = email

        if not valid_user(username):
            signup_error = True
            params['user_error'] = "Invalid username"
        else:
            # Handles checking if a username already exists.
            # TODO: Should probably make this a function to clean up the code.
            u = db.GqlQuery("Select * FROM User WHERE name = :n", n=username)
            out = []
            for x in u:
                out.append(x.name)
            if len(out) > 0:
                signup_error = True
                params['user_error'] = "User already Exists"
            else:
                params['username'] = username

        if not valid_pass(password):
            signup_error = True
            params['pass_error'] = "Invalid password"

        if password != verify:
            signup_error = True
            params['match_error'] = "Passwords do no match"

        # If the signup is valid we create the user in the database.
        if signup_error:
            self.render("signup.html", user={}, **params)
        else:
            salt = make_salt()
            h = hashlib.sha256(username + password + salt).hexdigest()
            h = '%s|%s' % (h, salt)
            u = User(name=username, password=h, email=email)
            u.put()
            user_id = u.key().id()
            cookie = (str(user_id) +
                      '|' +
                      hashlib.sha256(str(user_id) + 'blog').hexdigest())
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie',
                                             'name=%s; Path=/' % cookie)
            self.redirect("/welcome")


class LoginPage(Handler):
    """

    Class that handles creating and submitting the login page and information.
    The login information is then added to a cookie with enctrypted info.

    """
    def get(self):
        user = user_logged_in(self)
        self.render('login.html', user=user)

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        u = db.GqlQuery("SELECT * FROM User WHERE name=:n", n=username).get()
        if u:
            uid = u.key().id()
            salt = u.password.split('|')[1]
            h = hashlib.sha256(username + password + salt).hexdigest()
            if username == u.name and h == u.password.split('|')[0]:
                cookie = (str(uid) +
                          '|' +
                          hashlib.sha256(str(uid) + 'blog').hexdigest())
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie',
                                                 'name=%s; Path=/' % cookie)
                self.redirect('/welcome')
        error = "Could not login with Username and password"
        self.render('login.html', user={}, user_error=error)


class LogoutPage(Handler):
    """

    Class that handles user logout.

    """
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie',
                                         'name=''; Path=/')
        self.redirect('/signup')


class UserPage(Handler):
    """

    Class that handles rendering a page welcoming a user at login.

    """
    def get(self):
        user = user_logged_in(self)
        if user:
            self.render("userpage.html", user=user)
        else:
            self.redirect('/login')


class PostPage(Handler):
    """

    Class that handles rendering the form to create a post and submits a post
    to the database.

    """
    def get(self):
        user = user_logged_in(self)
        if user:
            self.render("form.html", user=user)
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get("subject")
        content = self.request.get("content")
        user = user_logged_in(self)

        if not user.logged_in:
            self.redirect('/login')
        if title and content:
            p = Post(title=title,
                     content=content,
                     submitter_id=user.key().id(),
                     submitter=user.name,
                     likes=[])
            p.put()
            post_id = p.key().id()
            self.redirect('/' + str(post_id))
        else:
            error = "Enter a title and content!"
            self.render("form.html", error=error)


class EditPost(Handler):
    """

    Class that handles rendering a page to edit a user's post and submits the
    updated page to the database.

    """
    def get(self, post_id):
        logged_in = False
        user = user_logged_in(self)
        if user:
            p = Post.get_by_id(int(post_id))
            self.render("editpost.html", user=user, post=p)
        else:
            self.redirect("/login")

    def post(self, post_id):
        logged_in = False
        user = user_logged_in(self)
        p = Post.get_by_id(int(post_id))
        if user and user.key().id() == p.submitter_id:
            p.title = self.request.get("subject")
            p.content = self.request.get("content")
            p.put()
            self.redirect("/")
        else:
            self.redirect("/login")


class DeletePost(Handler):
    """

    Class that handles the request to delete a post and remove it from the
    database.

    """
    def get(self, post_id):
        user = user_logged_in(self)
        p = Post.get_by_id(int(post_id))
        if user.key().id() == p.submitter_id:
            p.delete()
        self.redirect("/")


class LikePage(Handler):
    """

    Class that handles the request to like a different user's post.

    """
    def get(self, post_id):
        user = user_logged_in(self)
        p = Post.get_by_id(int(post_id))
        if user and user.key().id() != p.submitter_id:
            if user.name not in p.likes:
                p.likes.append(user.name)
                p.put()
            self.redirect("/")
        else:
            self.redirect("/login")

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', PostPage),
                               ('/editpost/(\d+)', EditPost),
                               ('/deletepost/(\d+)', DeletePost),
                               ('/signup', NewUser),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/welcome', UserPage),
                               ('/like/(\d+)', LikePage),
                               ('/(\d+)', NewEntry)],
                              debug=True)
