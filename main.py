from google.appengine.ext.webapp.util import run_wsgi_app
import os
import webapp2
import helper

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
                               ('/home', helper.FrontPageDefault),
                               ('/signup', helper.Signup),
                               ('/login', helper.Login),
                               ('/logout', helper.Logout),
                               ('/home' + PAGE_RE, helper.FrontPage)
                               ], debug=True)

def main():
    run_wsgi_app(app)

if __name__ == "__main__":
    main()