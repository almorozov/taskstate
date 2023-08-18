import os

FLASK_APP = 'app.py'
FLASK_ENV = 'CTFdev'
SQLALCHEMY_DATABASE_URI = 'sqlite:///'+os.path.abspath(os.getcwd())+"/data/"+'taskstate.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
