from flask import Flask

def create_app():
    from .sconfig import SECRET_KEY
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    app.secret_key = SECRET_KEY
    return app