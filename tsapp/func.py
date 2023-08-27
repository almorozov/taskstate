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


def f_task_acl(task, rid, uid):
    res = False
    if rid == 2:
        res = True
    if rid == 1:
        if task.private == False or (task.uid1 == uid and task.private == True):
            res = True
    if rid == 0:
        if task.uid1 == uid:
            res = True
    return res