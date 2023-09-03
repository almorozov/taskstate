import os

file_log = os.path.abspath(os.getcwd()) + "/logs/TS_Events.log"
FLASK_APP = 'TS_app'
FLASK_ENV = 'CTFdev'
SQLALCHEMY_DATABASE_URI = 'sqlite:///'+os.path.abspath(os.getcwd())+"/data/taskstate.db"
SQLALCHEMY_TRACK_MODIFICATIONS = False
