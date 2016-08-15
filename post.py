from google.appengine.ext import db


class Post(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    submitter_id = db.IntegerProperty(required=True)
    submitter = db.StringProperty(required=True)
    likes = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
