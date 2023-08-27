from flask import Flask
from .sconfig import rteam

def create_app():
    from .sconfig import SECRET_KEY
    app = Flask(__name__)
    app.config.from_pyfile('config.py')
    app.secret_key = SECRET_KEY
    return app


def f_rid_get(request):
    rid = 0
    if request.cookies.get('rid'):
        rid = int(request.cookies.get('rid'))
        if rid >= len(rteam):
            rid = 0
    return rid


def f_task_acl(task, rid):
    return True