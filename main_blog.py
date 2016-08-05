import os
import jinja2
import webapp2
import re
import hashlib
import string
import random

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
    user = None
    u = self.request.cookies.get('name')
    # TODO: Update cookie with encryption!!
    if u:
        user = User.get_by_id(int(u))
        user.logged_in = True
        return user
    else:
        return user


class Handler(webapp2.RequestHandler):
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
    created = db.DateTimeProperty(auto_now_add=True)


class User(db.Model):
    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add=True)


class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post "
                            "ORDER BY created DESC LIMIT 10")
        user = user_logged_in(self)

        self.render("posts.html",
                    posts=posts,
                    user=user)


class NewEntry(Handler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        user = user_logged_in(self)
        user_id = None
        if user:
            user_id = user.key().id()
        self.render("postpage.html",
                    user=user,
                    user_id=user_id,
                    post=post)


class NewUser(Handler):
    def get(self):
        self.render("signup.html", user={})

    def post(self):
        signup_error = False
        params = {}
        email_valid = True
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if not valid_email(email):
            signup_error = True
            params['email_error'] = "Invalid email"
        else:
            params['email'] = email

        if not valid_user(username):
            signup_error = True
            params['user_error'] = "Invalid username"
        else:
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

        if signup_error:
            self.render("signup.html", user={}, **params)
        else:
            salt = make_salt()
            h = hashlib.sha256(username + password + salt).hexdigest()
            h = '%s|%s' % (h, salt)
            u = User(name=username, password=h, email=email)
            u.put()
            user_id = u.key().id()
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie',
                                             'name=%s; Path=/' % str(user_id))
            self.redirect("/welcome")


class LoginPage(Handler):
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
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie',
                                                 'name=%s; Path=/' % str(uid))
                self.redirect('/welcome')
        # else:
        error = "Could not login with Username and password"
        self.render('login.html', user={}, user_error=error)


class LogoutPage(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.headers.add_header('Set-Cookie',
                                         'name=''; Path=/')
        self.redirect('/signup')


class UserPage(Handler):
    def get(self):
        user = user_logged_in(self)
        if user:
            self.render("userpage.html", user=user)
        else:
            self.redirect('/login')


class PostPage(Handler):
    def get(self):
        user = user_logged_in(self)
        if user:
            self.render("form.html", user=user)
        else:
            self.redirect('/login')

    def post(self):
        title = self.request.get("subject")
        content = self.request.get("content")
        u = self.request.cookies.get('name')
        if u:
            logged_in = True
            user_id = int(u)
            username = User.get_by_id(int(u))
        else:
            redirect('/login')
        if title and content:
            p = Post(title=title,
                     content=content,
                     submitter_id=user_id,
                     submitter=username.name)
            p.put()
            post_id = p.key().id()
            self.redirect('/' + str(post_id))
        else:
            error = "Enter a title and content!"
            self.render("form.html", error=error)


class EditPost(Handler):
    def get(self, post_id):
        logged_in = False
        user = user_logged_in(self)
        p = Post.get_by_id(int(post_id))
        self.render("editpost.html", user=user, post=p)

    def post(self, post_id):
        p = Post.get_by_id(int(post_id))
        p.title = self.request.get("subject")
        p.content = self.request.get("content")
        p.put()
        self.redirect("/")


class DeletePost(Handler):
    def get(self, post_id):
        user = user_logged_in(self)
        p = Post.get_by_id(int(post_id))
        if user.key().id() == p.submitter_id:
            p.delete()
        self.redirect("/")

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/newpost', PostPage),
                               ('/editpost/(\d+)', EditPost),
                               ('/deletepost/(\d+)', DeletePost),
                               ('/signup', NewUser),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/welcome', UserPage),
                               ('/(\d+)', NewEntry)],
                              debug=True)
