from flask import Flask, render_template, render_template_string, request, url_for, redirect, flash, make_response
from sqlalchemy import and_, or_, not_
from datetime import datetime, date
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
import logging
from flask.logging import default_handler
from logging.handlers import RotatingFileHandler
import time
import os

from .models import TS_Task, TS_User, db
from .sconfig import desteam, tstatus, rteam
from .func import *

app = create_app()
db.init_app(app)
manager = LoginManager(app)


@manager.user_loader
def load_user(user_id):
    return TS_User.query.get(user_id)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/myprofile')
@login_required
def myprofile():
#    app.logger.info('[FUNC] [/MyProfile] [Succeess] User:<%s>',current_user.login)
    rid = f_rid_get(request)
    return render_template("myprofile.html", user=current_user, rteam=rteam, rid=rid)


@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == "POST":
        ulogin = request.form['login']
        upassword = request.form['password']
        user = TS_User.query.filter_by(login=ulogin).first()
        if user and check_password_hash(user.password, upassword):
            login_user(user)
            resp = make_response(redirect(url_for('myprofile')))
            resp.set_cookie('rid', str(user.rid))
#            app.logger.info('[AUTH] [LOGIN] [Succeess] User:<%s>', current_user.login)
            return resp
        else:
            flash('Login or password incorrect')
#            app.logger.warning('[AUTH] [LOGIN] [Failed] User:<%s> Password:<%s>', ulogin, upassword)
            return redirect(url_for('login'))
    else:
        return render_template("login.html")


@app.route('/logout', methods=['POST','GET'])
@login_required
def logout():
#    app.logger.info('[AUTH] [LOGOUT] [Succeess] User:<%s>', current_user.login)
    logout_user()
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('rid', "", 0)
    return resp


@app.route('/reg', methods=['POST','GET'])
def reg():
    if request.method == "POST":
        ulogin=request.form['login']
        upassword=request.form['password']
        if not(ulogin or upassword):
            flash('Please, fill fileds: login, password')
            return redirect('/reg')
        elif not(TS_User.query.filter_by(login=ulogin).first()) and ulogin and upassword:
            user = TS_User(login=ulogin, password=generate_password_hash(upassword), email=request.form['email'], rid=0, token="")
            try:
                db.session.add(user)
                db.session.commit()
#                app.logger.info('[AUTH] [REG] [Succeess] User:<%s>', ulogin)
                return redirect('/login')
            except:
#                app.logger.error('[AUTH] [REG] [Failed] User:<%s>. Error DB insert.', ulogin)
                flash('Error DB insert')
                return redirect('/reg')
        else:
#            app.logger.warning('[AUTH] [REG] [Failed] Please, enter other login or not null login or not null password')
            flash('Please, enter other login or not null login or not null password')
            return redirect('/reg')
    else:
        return render_template("reg.html")


@app.after_request
def redirect_to_login(response):
    if response.status_code == 401:
        return redirect('/login')
    return response


@app.route('/mytask')
@login_required
def mytask():
    tasks = TS_Task.query.filter(TS_Task.uid1==current_user.id).order_by(TS_Task.date.desc()).all()
    return render_template('task_mylist.html', tasks=tasks, desteam=desteam, tstatus=tstatus)


@app.route('/taskcreate', methods=['POST'])
@login_required
def taskcreate():
    if request.method == "POST":
        if (len(request.form['title']) > 2 and int(request.form['did']) and bool(request.form['private'])):
            task = TS_Task(did=int(request.form['did']), title=request.form['title'], description=request.form['description'], private=eval(request.form['private']), uid1=current_user.id, uid2=-1)
            try:
                db.session.add(task)
                db.session.commit()
                #app.logger.info('[FUNC] [/CreateTicket] [Succeess] User:<%s> Data:<%s>',current_user.login, ticket)
                return redirect(url_for('mytask'))
            except:
                #app.logger.error('[FUNC] [/CreateTicket] [Failed] User:<%s> Error DB insert',current_user.login)
                flash('Error DB insert')
                return redirect(url_for('mytask'))
        else:
            flash('Please, enter all rewuired data!')
            return redirect(url_for('mytask'))
    else:
        return redirect(url_for('mytask'))


@app.route('/task/<int:tid>')
@login_required
def task_detail(tid):
    task = TS_Task.query.filter(TS_Task.tid==tid).order_by(TS_Task.date.desc()).first()
    rid = f_rid_get(request)
    if task:
        task_access = f_task_acl(task, rid, current_user.id)
        if task_access:
            user2 = TS_User.query.filter(TS_User.id==task.uid2).order_by(TS_User.date.desc()).first()
            #app.logger.info('[FUNC] [/ticket] [Succeess] User:<%s> Read ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
            return render_template("task_detail.html", task=task, tstatus=tstatus, desteam=desteam, user2=user2)
        else:
            return redirect(url_for('tasklist'))
    else:
        return redirect(url_for('tasklist'))


@app.route('/task/<int:tid>/edit', methods=['POST','GET'])
@login_required
def task_edit(tid):
    task = TS_Task.query.filter(and_(TS_Task.uid1==current_user.id, TS_Task.tid==tid)).order_by(TS_Task.date.desc()).first()
    if task:
        if request.method == "POST":
            if (len(request.form['title']) > 2 and int(request.form['did']) and bool(request.form['private'])):
                task.title = request.form['title']
                task.description = request.form['description']
                task.did = int(request.form['did'])
                task.private = eval(request.form['private'])
                try:
                    db.session.commit()
#                    app.logger.info('[FUNC] [/ticket/edit] [Succeess] User:<%s> Edit ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
                    return redirect(url_for('mytask'))
                except:
#                    app.logger.error('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>. Error DB insert/', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
                    flash('Error DB insert')
                    return redirect('/task/' + tid + '/edit')
            else:
                flash('Please, enter all rewuired data!')
                return redirect('/task/' + tid + '/edit')
        else:
            return render_template("task_edit.html", task=task, desteam=desteam)
    else:
#        app.logger.warning('[FUNC] [/ticket/edit] [Failed] User:<%s> Edit ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
        return redirect(url_for('mytask'))


@app.route('/task/<int:tid>/del')
@login_required
def task_del(tid):
    task = TS_Task.query.filter(and_(TS_Task.uid1==current_user.id, TS_Task.tid==tid)).order_by(TS_Task.date.desc()).first()
    if task:
        try:
            db.session.delete(task)
            db.session.commit()
#            app.logger.info('[FUNC] [/ticket/del] [Succeess] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
        except:
#            app.logger.error('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>. Error DB delete!', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
            return "Error DB delete!"
#    else:
#        app.logger.warning('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
    return redirect(url_for('mytask'))


@app.route('/tasklist')
@login_required
def tasklist():
    rid = f_rid_get(request)
    users = TS_User.query.order_by(TS_User.date.desc()).all()
    if rid == 2:
        tasks = TS_Task.query.order_by(TS_Task.date.desc()).all()
    if rid == 1:
        tasks = TS_Task.query.filter(or_(TS_Task.private==False, and_(TS_Task.uid1==current_user.id, TS_Task.private==True))).order_by(TS_Task.date.desc()).all()
    if rid == 0:
        tasks = TS_Task.query.filter(TS_Task.uid1==current_user.id).order_by(TS_Task.date.desc()).all()
    return render_template('task_list.html', tasks=tasks, desteam=desteam, tstatus=tstatus, users=users)


@app.route('/task/<int:tid>/towork')
@login_required
def task_towork(tid):
    task = TS_Task.query.filter(TS_Task.tid==tid).order_by(TS_Task.date.desc()).first()
    rid = f_rid_get(request)
    if task:
        task_access = f_task_acl(task, rid, current_user.id)
        if task_access:
            task.uid2 = current_user.id
            try:
                db.session.commit()
    #            app.logger.info('[FUNC] [/ticket/del] [Succeess] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
            except:
    #            app.logger.error('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>. Error DB delete!', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
                return "Error DB delete!"
#    else:
#        app.logger.warning('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
    return redirect(url_for('tasklist'))


@app.route('/kanban')
@login_required
def kanban():
    tasks = TS_Task.query.filter(TS_Task.uid2==current_user.id).order_by(TS_Task.date.desc()).all()
    return render_template('task_kanban.html', tasks=tasks, desteam=desteam, tstatus=tstatus, login=current_user.login)


@app.route('/task/<int:tid>/bstatus')
@login_required
def task_bstatus(tid):
    task = TS_Task.query.filter(TS_Task.tid==tid).order_by(TS_Task.date.desc()).first()
    rid = f_rid_get(request)
    if task:
        task_access = f_task_acl(task, rid, current_user.id)
        if task_access:
            if task.kstatus != 0:
                task.kstatus -= 1
            try:
                db.session.commit()
    #            app.logger.info('[FUNC] [/ticket/del] [Succeess] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
            except:
    #            app.logger.error('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>. Error DB delete!', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
                return "Error DB delete!"
#    else:
#        app.logger.warning('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
    return redirect(url_for('kanban'))


@app.route('/task/<int:tid>/nstatus')
@login_required
def task_nstatus(tid):
    task = TS_Task.query.filter(TS_Task.tid==tid).order_by(TS_Task.date.desc()).first()
    rid = f_rid_get(request)
    if task:
        task_access = f_task_acl(task, rid, current_user.id)
        if task_access:
            if task.kstatus != 2:
                task.kstatus += 1
            try:
                db.session.commit()
    #            app.logger.info('[FUNC] [/ticket/del] [Succeess] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
            except:
    #            app.logger.error('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>. Error DB delete!', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
                return "Error DB delete!"
#    else:
#        app.logger.warning('[FUNC] [/ticket/del] [Failed] User:<%s> Del ticket: <%s> <%s> pilot: <%s>', current_user.login, ticket.tid, ticket.fpid, ticket.SFP_Users.login)
    return redirect(url_for('kanban'))


@app.route('/userstatus')
@login_required
def userstatus():
    users = TS_User.query.order_by(TS_User.login.asc()).all()
    return render_template("userstatus.html", users=users)


@app.route('/search', methods=['GET'])
@login_required
def search():
    tsearch = request.args.get('search')
    if tsearch:
        rid = f_rid_get(request)
        if rid == 2:
            tasks = TS_Task.query.filter(TS_Task.title.contains(tsearch)).order_by(TS_Task.date.desc()).all()
        if rid == 1:
            tasks = TS_Task.query.filter(and_(or_(TS_Task.private==False, and_(TS_Task.uid1==current_user.id, TS_Task.private==True)), TS_Task.title.contains(tsearch))).order_by(TS_Task.date.desc()).all()
        if rid == 0:
            tasks = TS_Task.query.filter(and_(TS_Task.uid1==current_user.id, TS_Task.title.contains(tsearch))).order_by(TS_Task.date.desc()).all()
#            app.logger.info('[FUNC] [/search] [Succeess] User:<%s> Data:<%s>',current_user.login, tsearch)
        return render_template("searchlist.html", tasks=tasks, tstatus=tstatus, tsearch=render_template_string(tsearch))
        #return render_template_string(tsearch)
    else:
        return redirect(url_for('index'))