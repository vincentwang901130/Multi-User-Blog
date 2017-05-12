import hashlib
import os
import random
from string import letters

import helper
import webapp2
from google.appengine.ext import db


# **********
# --Models--
# **********


class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(default=0)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    def render(self):
        timeformat = "%H:%M %b %d, %Y"
        self._render_text = self.content.replace('\n', '<br>')
        creattime = self.created.strftime(timeformat)
        edittime = self.last_modified.strftime(timeformat)
        if creattime == edittime:
            timestamp = "Created on " + creattime + " by " + self.getUserName()
        else:
            timestamp = "Edited on " + edittime + " by " + self.getUserName()
        return helper.jinja_render_str("post.html",
                                       p=self, timestamp=timestamp)

    @classmethod
    def deletecomment(cls, post_id):
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id)
        if comments:
            for cmt in comments:
                cmt.delete()

    @classmethod
    def deletelike(cls, post_id):
        likes = db.GqlQuery("select * from Like where post_id = " + post_id)
        if likes:
            for like in likes:
                like.delete()


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class Comment(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    @classmethod
    def users_key(cls, group='default'):
        return db.Key.from_path('users', group)

    @classmethod
    def make_salt(cls, length=5):
        return ''.join(random.choice(letters) for x in xrange(length))

    @classmethod
    def make_pw_hash(cls, name, pw, salt=None):
        if not salt:
            salt = cls.make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

    @classmethod
    def verify_pw(cls, name, password, h):
        salt = h.split(',')[0]
        return h == cls.make_pw_hash(name, password, salt)

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=cls.users_key())

    @classmethod
    def by_name(cls, name):
        usr = User.all().filter('name =', name).get()
        return usr

    @classmethod
    def by_email(cls, email):
        usr = User.all().filter('email =', email).get()
        return usr

    @classmethod
    def register(cls, name, pw, email):
        pw_hash = cls.make_pw_hash(name, pw)
        return User(parent=cls.users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, entry, pw):
        msg = None
        username = ""
        user = None
        if helper.valid_email(entry):
            user = cls.by_email(entry)
            if user:
                username = user.name
            else:
                msg = [1, "email not exists"]
        else:
            username = entry
            user = cls.by_name(entry)
        if user:
            if cls.verify_pw(username, pw, user.pw_hash):
                msg = [0, user]
            else:
                msg = [1, "incorrect password!"]
        else:
            msg = [1, "user not exist"]
        return msg

# ***********
# --Hanlder--
# ***********


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        params['path'] = self.path
        return helper.jinja_render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = helper.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and helper.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        self.path = self.request.path


# render the front page of the blog
class BlogFront(BlogHandler):
    def get(self):
        deleted_post_id = self.request.get('deleted_post_id')
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts=posts, deleted_post_id=deleted_post_id)


# render the post detail page
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + " order by created desc")
        if not post:
            self.error(404)
            return

        error = self.request.get('error')
        self.render("permalink.html", post=post,
                    comments=comments, error=error)


class likePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        if self.user:
            postlike = db.GqlQuery("select * from Like where post_id = " +
                                   post_id + " and user_id = " +
                                   str(self.user.key().id()))
            if self.user.key().id() == post.user_id:
                self.redirect("/blog/" + post_id +
                              "?error=You cannot like your own post")
                return
            elif postlike.count() == 0:
                newlike = Like(parent=blog_key(),
                               user_id=self.user.key().id(),
                               post_id=int(post_id))
                post.likes += 1
                newlike.put()
                post.put()
                self.redirect("/blog/" + post_id)
            elif postlike.count() != 0:
                # Like.remove(post_id, str(self.user.key().id()))
                postlike[0].delete()
                post.likes -= 1
                post.put()
                self.redirect("/blog/" + post_id)
        else:
            self.redirect("/login?error=Please login to like")
            return
        likes = db.GqlQuery("select * from Like where post_id=" + post_id)
        # render the page
        self.render("permalink.html", post=post, noOfLikes=likes.count())


class AddComment(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/login?error=Please login to comment")
            return
        else:
            self.render('newcomment.html')

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        newcomment = ""
        if self.user:
            if(self.request.get('comment')):
                newcomment = Comment(parent=blog_key(),
                                     user_id=self.user.key().id(),
                                     post_id=int(post_id),
                                     comment=self.request.get('comment'))
                newcomment.put()
                self.redirect("/blog/" + post_id)
                return
        else:
            self.redirect("/login?error=Please login to first")
            return
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")
        # render the page
        self.render("permalink.html", post=post, comments=comments)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")
            return

    def post(self):
        if not self.user:
            self.redirect('/blog')
            return

        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(parent=blog_key(), user_id=self.user.key().id(),
                        subject=subject, content=content)
            post.put()
            self.redirect('/blog/' + str(post.key().id()))
            return
        else:
            error = "Subject and content cannot be empty"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


class EditPost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                self.render("editpost.html", subject=post.subject,
                            content=post.content)
            else:
                self.redirect("/blog/" + post_id + "?error=Only owner of " +
                              "this post can edit this post.")
                return
        else:
            self.redirect("/login?error=Please login to edit")
            return

    def post(self, post_id):
        if not self.user:
            self.redirect("/login?error=Please login to edit")
            return
        if post.user_id == self.user.key().id():
            subject = self.request.get('subject')
            content = self.request.get('content')
            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                if post is not None:
                    post.subject = subject
                    post.content = content
                    post.put()
                    self.redirect('/blog/%s' % post_id)
                    return
                else:
                    self.redirect('/')
                    return
            else:
                error = "Subject and content can not be empty!"
                self.render("editpost.html", subject=subject,
                            content=content, error=error)
        else:
            self.redirect("/blog/" + post_id + "?error=Only owner of " +
                          "this post can edit this post.")
            return


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                post.deletecomment(post_id)
                post.deletelike(post_id)
                self.redirect("/?deleted_post_id=" + post_id)
                return
            else:
                self.redirect("/blog/" + post_id +
                              "?error=Only owner of this post can delete.")
                return
        else:
            self.redirect("/login?error=You need to login to edit this post")
            return


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(comment_id),
                                   parent=blog_key())
            cmt = db.get(key)
            if cmt.user_id == self.user.key().id():
                self.render("editcomment.html", comment=cmt.comment)
            else:
                self.redirect(
                    "/blog/" + post_id + "?error=You need to "
                    "be the owner of this comment to edit.")
                return
        else:
            self.redirect(
                "/login?error=You need to login to edit your comment.")
            return

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')
            return
        comment = self.request.get('comment')
        if cmt.user_id == self.user.key().id():
            if comment:
                key = db.Key.from_path('Comment', int(
                    comment_id), parent=blog_key())
                cmt = db.get(key)
                if cmt is not None:
                    cmt.comment = comment
                    cmt.put()
                    self.redirect("/blog/" + post_id)
                    return
                else:
                    self.redirect('/')
                    return
            else:
                error = "comment cannot be empty"
                self.redirect("editpost.html", subject=subject,
                              content=content,
                              error=error)
                return
        else:
            self.redirect(
                "/blog/" + post_id + "?error=You need to "
                "be the owner of this comment to edit.")
            return


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(
                comment_id), parent=blog_key())
            cmt = db.get(key)
            if cmt.user_id and cmt.user_id == self.user.key().id():
                cmt.delete()
                self.redirect("/blog/" + post_id)
                return
            else:
                self.redirect(
                    "/blog/" + post_id + "?error=You need to be "
                    "the owner of this comment to delete.")
                return
        else:
            self.redirect("/login?error=You need to "
                          "login to delete this comment.")
            return


class Signup(BlogHandler):
    def get(self):
        self.render("register.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not helper.valid_username(self.username):
            params['error_username'] = "The username is not valid."
            have_error = True

        if not helper.valid_password(self.password):
            params['error_password'] = "The password is not valid."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "The passwords does not match."
            have_error = True

        if not helper.valid_email(self.email):
            params['error_email'] = "The email address is not valid."
            have_error = True

        if have_error:
            self.render('register.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # Make sure the user doesn't already exist
        if User.by_name(self.username):
            msg = 'The user already exists.'
            self.render('register.html', error_username=msg)
        elif User.by_email(self.email):
            msg = 'The email already exists.'
            self.render('register.html', error_email=msg)
        else:
            usr = User.register(self.username, self.password, self.email)
            usr.put()
            self.login(usr)
            self.redirect('/')
            return


class Login(BlogHandler):
    errormsg = ""
    msg = None

    def get(self):
        self.render('login.html', error=self.request.get('error'))

    def post(self):
        entry = self.request.get('username')
        password = self.request.get('password')
        msg = User.login(entry, password)
        if msg[0] == 0:
            user = msg[1]
            self.login(user)
            self.redirect('/?')
            return
        elif msg[0] == 1:
            errormsg = msg[1]
            self.render('login.html', error=errormsg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')
        return


app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/register', Register),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/like/([0-9]+)', likePost),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/addcomment/([0-9]+)', AddComment),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/newpost', NewPost)
                               ], debug=True)
