import hashlib
import hmac
import os
import random
import re
from string import letters

import jinja2
import webapp2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
secret = "OhCanada"

# *********
# --tools--
# *********


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PWD_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PWD_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


# **********
# --Models--
# **********


class Post(db.Model):
    user_id = db.IntegerProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
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
        return render_str("post.html", p=self, timestamp=timestamp)

    @classmethod
    def deletecomment(cls, post_id):
        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id)
        if comments:
            for cmt in comments:
                cmt.delete()


class Like(db.Model):
    user_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)

    def getUserName(self):
        user = User.by_id(self.user_id)
        return user.name

    # @classmethod
    # def remove(cls, post_id, user_id):
    #     likes = db.GqlQuery("select * from Like where post_id = " +
    #                         post_id + "and user_id=" + user_id)
    #     if likes:
    #         for like in likes:
    #             like.delete()


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
        if valid_email(entry):
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
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

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
        likes = db.GqlQuery("select * from Like where post_id=" + post_id)
        if not post:
            self.error(404)
            return

        error = self.request.get('error')
        self.render("permalink.html", post=post, noOfLikes=likes.count(),
                    comments=comments, error=error)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not post:
            self.error(404)
            return
        newcomment = ""
        if self.user:
            # On clicking like, post-like value increases.
            if(self.request.get('like') and
               self.request.get('like') == "update"):
                likes = db.GqlQuery("select * from Like where post_id = " +
                                    post_id + " and user_id = " +
                                    str(self.user.key().id()))
                if self.user.key().id() == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your own post")
                    return
                elif likes.count() == 0:
                    newlike = Like(parent=blog_key(),
                                   user_id=self.user.key().id(),
                                   post_id=int(post_id))
                    newlike.put()
                    self.redirect("/blog/" + post_id)
                elif likes.count() != 0:
                    # Like.remove(post_id, str(self.user.key().id()))
                    likes[0].delete()
                    self.redirect("/blog/" + post_id)
                    # On commenting, it creates new comment tuple
            if(self.request.get('comment')):
                newcomment = Comment(parent=blog_key(),
                                     user_id=self.user.key().id(),
                                     post_id=int(post_id),
                                     comment=self.request.get('comment'))
                newcomment.put()
                self.redirect("/blog/" + post_id)
        else:
            self.redirect("/login?error=Please login to edit")
            return

        comments = db.GqlQuery("select * from Comment where post_id = " +
                               post_id + "order by created desc")
        likes = db.GqlQuery("select * from Like where post_id=" + post_id)
        # render the page
        self.render("permalink.html", post=post,
                    comments=comments, noOfLikes=likes.count(),
                    new=newcomment)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            post = Post(parent=blog_key(), user_id=self.user.key().id(),
                        subject=subject, content=content)
            post.put()
            self.redirect('/blog/' + str(post.key().id()))
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
        else:
            self.redirect("/login?error=Please login to edit")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog')
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.subject = subject
            post.content = content
            post.put()
            self.redirect('/blog/%s' % post_id)
        else:
            error = "Subject and content can not be empty!"
            self.render("editpost.html", subject=subject,
                        content=content, error=error)


class DeletePost(BlogHandler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.user_id == self.user.key().id():
                post.delete()
                post.deletecomment(post_id)
                self.redirect("/?deleted_post_id=" + post_id)
            else:
                self.redirect("/blog/" + post_id +
                              "?error=Only owner of this post can delete.")
        else:
            self.redirect("/login?error=You need to login to edit this post")


class EditComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(
                comment_id), parent=blog_key())
            cmt = db.get(key)
            if cmt.user_id == self.user.key().id():
                self.render("editcomment.html", comment=cmt.comment)
            else:
                self.redirect(
                    "/blog/" + post_id + "?error=You need to "
                    "be the owner of this comment to edit.")
        else:
            self.redirect(
                "/login?error=You need to login to edit your comment.")

    def post(self, post_id, comment_id):
        if not self.user:
            self.redirect('/blog')
        comment = self.request.get('comment')
        if comment:
            key = db.Key.from_path('Comment', int(
                comment_id), parent=blog_key())
            cmt = db.get(key)
            cmt.comment = comment
            cmt.put()
            self.redirect("/blog/" + post_id)
        else:
            error = "comment cannot be empty"
            self.redirect("editpost.html", subject=subject, content=content,
                          error=error)


class DeleteComment(BlogHandler):
    def get(self, post_id, comment_id):
        if self.user:
            key = db.Key.from_path('Comment', int(
                comment_id), parent=blog_key())
            cmt = db.get(key)
            if cmt.user_id == self.user.key().id():
                cmt.delete()
                self.redirect("/blog/" + post_id)
            else:
                self.redirect(
                    "/blog/" + post_id + "?error=You need to be "
                    "the owner of this comment to delete.")
        else:
            slef.redirect("/login?error=You need to "
                          "login to delete this comment.")


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

        if not valid_username(self.username):
            params['error_username'] = "The username is not valid."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "The password is not valid."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "The passwords does not match."
            have_error = True

        if not valid_email(self.email):
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
        elif msg[0] == 1:
            errormsg = msg[1]
            self.render('login.html', error=errormsg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/')


app = webapp2.WSGIApplication([('/?', BlogFront),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/register', Register),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/deletepost/([0-9]+)', DeletePost),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/deletecomment/([0-9]+)/([0-9]+)',
                                DeleteComment),
                               ('/blog/editcomment/([0-9]+)/([0-9]+)',
                                EditComment),
                               ('/blog/newpost', NewPost)
                               ], debug=True)
