import os
import webapp2
import jinja2
import re
from string import letters
import hashlib
import hmac
import random
import string
from google.appengine.ext import db
secret = "iamsecret"

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
password_re = re.compile(r"^.{3,20}$")
email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    # Your code here
    salt = h.split(",")[1]
    if h.split(",")[0] == hashlib.sha256(name + pw + salt).hexdigest():
        return True
    else:
        return False


def check_pw_hash(username, password, db_password):
    salt = db_password.split(",")[1]
    pw = hashlib.sha256(username + password + salt).hexdigest()
    if db_password.split(",")[0] == pw:
        return True
    else:
        return False


def hash_str(s):
    return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


def valid_username(username):
    return USER_RE.match(str(username))


def check_username(username):
    db_username = db.GqlQuery(
        "select * from User where username = :username", username=username)
    name = db_username.get()
    if name:
        return 1
    else:
        return 0


def valid_password(password):
    return password_re.match(password)


def valid_email(email):
    return email_re.match(email)


def login(username, password):
    db_username = db.GqlQuery(
        "select * from User where username =:username", username=username)
    name = db_username.get()
    if name:
        if check_pw_hash(username, password, name.password):
            return True
        else:
            return False
    else:
        return False

# database

# comment database


class Comment_db(db.Model):
    post_id = db.IntegerProperty(required=True)
    posted_by = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# user database


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

# blog database


class Blog(db.Model):
    title = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    posted_by = db.StringProperty(required=True)
    likes = db.IntegerProperty(required=True)

# like database


class Like_db(db.Model):
    post_id = db.IntegerProperty(required=True)
    liked_by = db.StringProperty(required=True)

# blog
# Handler


class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def check_login(self):
        username = self.read_secure_cookie("username")
        if username:
            return True
        else:
            return False

# signup page


class Signup(Handler):

    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        distinct_username = check_username(username)
        if distinct_username == 1:
            distinct_username = 0
            params['error_username'] = "this username already exist"
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            username = str(username)
            password = str(make_pw_hash(username, password))
            a = User(username=username, password=password, email=email)
            a.put()
            username = self.set_secure_cookie("username", username)
            self.redirect('/blog/welcome')

# welcome page


class Welcome(Handler):

    def get(self):
        username = self.read_secure_cookie('username')
        if username:
            self.render('welcome.html', username=username)
        else:
            self.redirect('/blog/signup')

# login


class Login(Handler):

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if login(username, password):
            self.set_secure_cookie("username", str(username))
            self.redirect('/blog/welcome')
        else:
            self.render("login.html", error="invalid login")

# logout


class Logout(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'username =; Path=/')
        self.render("logout.html")
        self.redirect("/blog/login")

# Mainpage blog


class Mainpage(Handler):

    def get(self):

        posts = db.GqlQuery("select * from Blog order by created desc")
        comment = db.GqlQuery("select * from Comment_db order by created asc")
        if self.check_login():
            login = "logout"
            signup = ""
        else:
            login = "login"
            signup = "signup"
        self.render("front.html", posts=posts, login=login,
                    comment=comment, signup=signup)

# likes


class Like(Handler):

    def get(self, post_id):
        a = int(post_id)
        key = db.Key.from_path('Blog', int(post_id), parent=None)
        post = db.get(key)
        current_user = self.read_secure_cookie("username")
        if current_user:
            if post.posted_by == current_user:
                self.render("like.html", error="cannot like your own post")
            else:
                all_likes = db.GqlQuery(
                    "select * from Like_db where post_id =:post_id",
                     post_id=int(post_id))
                flag = 0
                if post.likes != 0:
                    likes = all_likes.get()
                    if likes.liked_by == current_user:
                        flag == 1
                        self.render("like.html", error="cannot like twice")
                    else:
                        a = Like_db(
                            post_id=int(post_id), liked_by=current_user)
                        a.put()
                        post.likes += 1
                        post.put()
                        self.redirect("/blog")
                else:
                    a = Like_db(post_id=int(post_id), liked_by=current_user)
                    a.put()
                    post.likes += 1
                    post.put()
                    self.redirect("/blog")
        else:
            self.render("signup.html")

# Newpage


class Newpage(Handler):

    def render_front(self, title="", post="", error=""):
        self.render("form.html", title=title, post=post, error=error)

    def get(self):
        if self.check_login():
            self.render_front()
        else:
            self.redirect("/blog/login")

    def post(self):
        if self.check_login():
            title = self.request.get("title")
            post = self.request.get("post")
            posted_by = self.request.cookies.get("username")
            username = posted_by.split('|')[0]
            if title and post:
                post = post.replace('\n', '<br>')
                b = 0
                a = Blog(title=title, post=post, posted_by=username, likes=b)
                a.put()
                a_id = a.key().id()
                self.redirect('/blog/'+str(a_id))
            else:
                self.render_front(
                    title=title, post=post, error="enter the valid details")
        else:
            self.redirect("/blog/login")

# comment submit


class Comment_submit(Handler):

    def post(self, post_id):
        current_user = self.read_secure_cookie("username")
        if current_user:
            comment = self.request.get('comment_textarea')
            if comment:
                a = Comment_db(
                    post_id=int(post_id),
                    posted_by=current_user,
                    comment=comment)
                a.put()
                self.redirect("/blog")
        else:
            self.redirect("/blog/login")

# comment edit


class Comment_edit(Handler):

    def get(self, comment_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            a = int(comment_id)
            key = db.Key.from_path('Comment_db', int(comment_id), parent=None)
            comment = db.get(key)
            if comment:
                if comment.posted_by == self.read_secure_cookie("username"):
                    self.render("comment_edit.html", a=comment)
                else:
                    self.render(
                        "like.html",
                         error="sorry! but you can edit only your post")
        else:
            self.redirect("/blog/login")

    def post(self, comment_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            comment_get = self.request.get('comment_edit')
            a = int(comment_id)
            key = db.Key.from_path('Comment_db', int(comment_id), parent=None)
            comment_row = db.get(key)
            if comment_row:
                if comment_row.posted_by == self.read_secure_cookie("username"):
                    comment_row.comment = comment
                    comment_row.put()
                    self.redirect("/blog")
        else:
            self.redirect("/blog/login")
# comment delete


class Comment_delete(Handler):

    def get(self, comment_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            a = int(comment_id)
            key = db.Key.from_path('Comment_db', int(comment_id), parent=None)
            comment = db.get(key)
            if comment:
                if comment.posted_by == self.read_secure_cookie("username"):
                    comment.delete()
                    self.render("like.html", error="comment delete")
                    self.redirect("/blog")
                else:
                    self.render(
                        "like.html",
                         error="sorry! but you can edit only your post")
        else:
            self.redirect("/blog/login")
# post edit


class Post_edit(Handler):

    def get(self, post_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            a = int(post_id)
            key = db.Key.from_path('Blog',
                int(post_id),
                parent=None)
            post = db.get(key)
            if post:
                if post.posted_by == self.read_secure_cookie("username"):
                    self.render("post_edit.html",
                     login="logout", a=post)
                else:
                    self.render(
                        "like.html",
                        error="sorry! but you can edit only your post")
        else:
            self.redirect("/blog/login")

    def post(self, post_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            edited_post = self.request.get('comment_edit')
            a = int(post_id)
            key = db.Key.from_path('Blog', int(post_id), parent=None)
            post_row = db.get(key)
            if post_row:
                if post_row.posted_by == self.read_secure_cookie("username"):
                    post_row.post = edited_post
                    post_row.put()
                    self.redirect("/blog")
        else:
            self.redirect("/blog/login")
# post delete


class Post_delete(Handler):

    def get(self, Post_id):
        curr_user = self.read_secure_cookie("username")
        if curr_user:
            a = int(Post_id)
            key = db.Key.from_path('Blog', int(Post_id), parent=None)
            post_row = db.get(key)
            if post_row:
                if post_row.posted_by == self.read_secure_cookie("username"):
                    post_row.delete()
                    self.render("like.html", error="post deleted")
                    self.redirect("/blog")
                else:
                    self.render(
                        "like.html",
                         error="sorry! but you can edit only your post")
        else:
            self.redirect("/blog/login")
# permalink


class Peralink(Handler):

    def get(self, a_id):
        a = int(a_id)
        key = db.Key.from_path('Blog', int(a_id), parent=None)
        post = db.get(key)
        if not post:
            self.write("error 404")
        else:
            self.render("permalink.html", posts=post)


app = webapp2.WSGIApplication([('/blog', Mainpage),
                               ('/blog/Newpage', Newpage),
                               ('/blog/([0-9]+)', Peralink),
                               ('/blog/signup', Signup),
                               ('/blog/welcome', Welcome),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/like/([0-9]+)', Like),
                               ('/blog/comment/([0-9]+)', Comment_submit),
                               ('/blog/comment_edit/([0-9]+)', Comment_edit),
                               ('/blog/delete/([0-9]+)', Comment_delete),
                               ('/blog/Post_edit/([0-9]+)', Post_edit),
                               ('/blog/Post/([0-9]+)', Post_delete)
                               ],
                              debug=True)
