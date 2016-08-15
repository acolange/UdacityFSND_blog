from google.appengine.ext import db


class Comment(db.Model):
    post_id = db.IntegerProperty(required=True)
    body = db.TextProperty(required=True)
    submitter_id = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
