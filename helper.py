from google.appengine.ext import db
from google.appengine.api import memcache
import os
import webapp2
import jinja2
import random
import string
import hashlib
import time
import hmac
import binascii
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

# Secret is generated using hexlify
SECRET = binascii.hexlify(os.urandom(50))

#### Jinja Template handler

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def encode(s):
    return "%s|%s" % (s, hash_str(s))

def decode(h):
    val = h.split('|')[0]
    if h == encode(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split('|')[0]
    return h ==  make_pw_hash(name, pw, salt)

class User(db.Model):
    """User DataBase"""
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    register_time = db.DateTimeProperty(auto_now = True)

class Main(db.Model):
    """Main Database"""
    content = db.TextProperty(required = False)

class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = encode(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val == None:
            return None
        else:
            return decode(cookie_val)

    ## login means set the cookie
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    ## logout means clear the cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

class Signup(MainHandler):
    username = ""
    username_error = ""
    password = ""
    password_error = ""
    verify = ""
    verify_error = ""
    email = ""
    email_error = ""
    referer = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = "",
                    verify = "", verify_error = "",
                    email = "", email_error = ""):
        self.render("signup.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error,
                    verify = verify, verify_error = verify_error,
                    email = email, email_error = email_error,
                    referer = self.referer)

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PASS_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_password(self, password):
        return self.PASS_RE.match(password)

    def valid_verify(self, password, verify):
        return password == verify
    
    def valid_email(self, email):
        return email or self.PASS_RE.match(email)

    def updateErrorMessages(self):
        self.username_error = "" if self.valid_username(self.username) else "That's not a valid username."
        self.password_error = "" if self.valid_password(self.password) else "That wasn't a valid password."
        self.verify_error = "" if self.valid_password(self.password) and self.valid_verify(self.password, self.verify) or not self.password_error == "" else "Your passwords didn't match."
        self.email_error = "" if self.valid_email(self.email) or self.email == "" else "That's not a valid email."
        if not (self.username_error == "" and self.password_error == ""
                and self.verify_error == "" and self.email_error == ""):
            self.password = ""
            self.verify = "" 

    def get(self):
        self.username = ""
        self.username_error = ""
        self.password = ""
        self.password_error = ""
        self.verify = ""
        self.verify_error = ""
        self.email = ""
        self.email_error = ""
        if not self.request.referer == self.request.url:
            self.referer = self.request.referer
        else: self.referer = self.referer
        self.render_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        self.referer = self.request.get('referer')
        self.updateErrorMessages()
        if self.username_error == "" and self.password_error == "" and self.verify_error == "" and self.email_error == "":
            users = db.GqlQuery("SELECT * FROM User")
            userList = []
            for user in users:
                userList.append(user.name)
            alreadyExist = self.username in userList
            if not alreadyExist:
                newuser = User(name = self.username,
                               pw_hash = make_pw_hash(self.username, self.password),
                               email = self.email)
                newuser.put()
                self.login(newuser)
                time.sleep(0.01)
                self.redirect("/home")
            else:
                self.username_error = "'%s' already exists." % self.username
                self.password = ""
                self.verify = ""
                self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)
        else:
            self.render_page(self.username, self.username_error,
                       self.password, self.password_error,
                       self.verify, self.verify_error,
                       self.email, self.email_error)

class Login(MainHandler):
    referer = ""
    def render_page(self, username = "", username_error = "", 
                    password = "", password_error = ""):
        self.render("login.html", username = username, username_error = username_error, 
                    password = password, password_error = password_error, referer = self.referer)
    def get(self):
        if not self.request.referer == self.request.url:
            if self.request.referer == None:
                self.referer = self.read_secure_cookie('referer')
            else:
                self.referer = self.request.referer
        else: self.referer = self.referer

        self.render_page()

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.referer = self.request.get('referer')
        
        exsitUser = db.GqlQuery("SELECT * FROM User WHERE name= :name_to_query", name_to_query = self.username)
        if exsitUser.get() != None:
            if valid_pw(self.username, self.password, exsitUser[0].pw_hash):
                self.login(exsitUser[0])
                self.redirect("/home")
            else:
                self.password_error = "Password is invalid!"
                self.render_page(self.username, "", "", self.password_error)
        else:
            self.username_error = "'%s' doesn't exist" % self.username
            self.render_page("", self.username_error, "", "")

class Logout(MainHandler):
    def get(self):
        self.logout()
        #ref = self.request.headers['Referer']
        self.redirect("/home/")

class FrontPageDefault(MainHandler):
    def get(self):
        self.redirect('/home/')

class FrontPage(MainHandler):
    def render_page(self, content, page_id):
        uid = self.read_secure_cookie('user_id')
        if uid == None:
            self.render("content.html", content = content, page_id = page_id, uid = '')
        else:
            user = User.get_by_id(int(uid))
            if user == None:
                self.render("content.html", content = content, page_id = page_id, uid = "")
            else:
                items_particular = self.request.get_all("particular")
                items_amount = self.request.get_all("amount")
                items_describe = self.request.get_all("description")
                self.render("expense.html", items_particular = items_particular,
                    items_amount = items_amount, items_describe = items_describe,
                    content = content, page_id = page_id, uid = user.name)

    def get(self, newpage):
        version = self.request.get('v')

        page_id = newpage.split('/')[1]
        if page_id == "":
            if not version == "":
                page = Main.get_by_key_name('.v%s' % version)
            else:
                page = Main.get_by_key_name('.')
        else:
            if not version == "":
                page = Main.get_by_key_name(page_id + '.v%s' % version)
            else:
                page = Main.get_by_key_name(page_id)

        if not page:
            if page_id == "":
                new = Main(key_name = '.')
                new.put()
                Main(key_name = '.v2').put()
                #time.sleep(0.1)
                self.redirect('/home/%s' % str(page_id))
            else:
                uid = self.read_secure_cookie('user_id')
                self.set_secure_cookie('referer', self.request.url)
                if uid == None:
                    self.redirect('/login', permanent=True)
                else:
                    user = User.get_by_id(int(uid))
                    if user == None:
                        self.redirect('/login')
        else:
            self.render_page(page.content, page_id)

