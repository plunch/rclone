import MySQLdb
from MySQLdb.cursors import DictCursor
import re
import datetime
import os
import base64
import smtplib
from urllib.parse import urlparse
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, send_from_directory, config
from flask.ext.login import LoginManager, login_user, logout_user, login_required, current_user
from models.user import User
from models.post import Post
from forgot_password_email import Mailer

app = Flask(__name__)
app.config.from_pyfile('conf_rclone.cfg')

lm = LoginManager()
lm.session_protection = 'strong'
lm.init_app(app)
lm.login_message='User not logged in. This incident will be reported'

lm.login_view = 'login'

def username_valid(u):
    return re.search('^[0-9a-zA-Z_-]{3,20}$') is not None

def password_valid(p):
    if len(pwd) < 6:
        return False
    else:
        return True

def email_valid(email):
    return '@' in email

def redirect_valid(uri):
    u = urlparse(uri)

    # Only redirect to the current host
    if u.netloc != '':
        return False

    if not u.scheme in ['http', 'https', 'mailto', '']:
        return False

    # Whoa...
    if '..' in u.path:
        return False
    return True

def generate_password():
    return (SystemRandom().choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!?.,_-="\':;/\\[]{}()<>|') for x in range(0,10))

# Do some function decoration, as it's nicer to always have an AttrDict for
# accessing the results of the DictCursor.
class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

def fetchalldecorator(method):
    def decorate_fetchall(self=None):
        return (AttrDict(d) for d in method(self))
    return decorate_fetchall

def fetchonedecorator(method):
    def decorate_fetchone(self=None):
        return AttrDict(method(self))
    return decorate_fetchone

def fetchmanydecorator(method):
    def decorate_fetchmany(self=None, size=0):
        return (AttrDict(d) for d in method(self, size))
    return decorate_fetchmany


DictCursor.fetchall = fetchalldecorator(DictCursor.fetchall)
DictCursor.fetchone = fetchonedecorator(DictCursor.fetchone)
DictCursor.fetchmany = fetchmanydecorator(DictCursor.fetchmany)

DictCursor.fetchallDict = fetchalldecorator(DictCursor.fetchallDict)
DictCursor.fetchoneDict = fetchonedecorator(DictCursor.fetchoneDict)
DictCursor.fetchmanyDict = fetchmanydecorator(DictCursor.fetchmanyDict)


@lm.user_loader
def load_user(userid):
    cur = g.db.cursor()
    cur.execute('select id, name, created from users where id = %s limit 1', (userid,))
    u = User()
    r = cur.fetchone()
    u.id = r.id
    u.name = str(r.name)
    u.created=r.created
    return u

@app.route('/logout')
def logout():
    logout_user()
    next = request.args.get('next')
    if not redirect_valid(next): next = None
    return redirect(next or url_for('index'))

def get_form_key():
    if 'csrfkey' not in session:
        session['csrfkey'] = str(base64.standard_b64encode(os.urandom(64)))
    return session['csrfkey']

@app.route('/login', methods=['GET', 'POST'])
def login():
    key = get_form_key()
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        tok = str(request.form['csrftoken'])
        if tok != key:
            return render_template('login.html', title='login', key=key)

        valid = True

        if not username_valid(user):
            flash('Username or password is not valid', category='error')
            valid=False
        if not password_valid(pwd):
            if valid: flash('Username or password is not valid', category='error')
            valid=False
        if current_user != None and current_user.is_authenticated():
            if valid: flash('Already logged in', category='error')
            valid=False

        if valid:
            cur = g.db.cursor()
            cur.execute("select id, name, created from users \
                         where name = %s and password = %s", (user, pwd))
            if cur.rowcount == 0:
                flash('Unknown user or wrong password', category='error')
                return render_template('login.html', title='login', key=key)

            u = User()
            r = cur.fetchone()
            u.id = r.id
            u.name = str(r.name)
            u.created=r.created

            flash('Successfully logged in. Welcome, ' + u.name, category='success')
            login_user(u, remember=request.form.get('remember', '') == 'on')

            next = request.args.get('next')
            if not redirect_valid(next): next = None
            return redirect(next or url_for('index'))
    return render_template('login.html', title='login', key=key)

@app.route('/login/new', methods=['GET', 'POST'])
def create_user():
    key = get_form_key()
    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

        valid = True

        if not username_valid(user):
            flash("Invalid username. Allowed characters are 'A-Z', '0-9', '_' and '-'. Username needs to be between 3 and 20 characters.", category='error')
            valid = False
        if not password_valid(pwd):
            flash('Password needs to be at least 6 characters', category='error')
            valid = False
        if not email_valid(email):
            flash('Email address is not valid', category='error')
            valid = False
        if current_user != None and current_user.is_authenticated():
            flash('You cannot create a new user while logged in')
            valid=False
        
        if valid:
            cur = g.db.cursor()
            cur.execute("select * from users where name = %s", (user,))
            if cur.rowcount == 0:
                cur.execute('insert into users (name, password) values (%s, %s)', (user, pwd))
                cur.execute("select id, name, created from users \
                            where name = %s and password = %s", (user, pwd))
                if cur.rowcount == 0:
                    abort(500)
                u = User()
                r = cur.fetchone()
                u.id = r.id
                u.name = str(r.name)
                u.created=r.created

                cur.execute('select id from user_line_types where visible = 1 and name = "email"')
                emailid = cur.fetchone().id
                cur.execute('insert into user_lines (user, type, value) values (%s, %s, %s)', (u.id, emailid, email))

                login_user(u)
                g.db.commit()
                flash('Welcome')
                return redirect(url_for('.index'))
            else:
                flash('Username taken', category='error')

    return render_template('new_login.html', title='create user', key=key)

@app.route('/login/forgot', methods=['GET', 'POST'])
def forgot_password():
    key = get_form_key()
    if request.method == 'POST':
        email = request.form['email']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)
        if not email_valid(email):
            flash('Email address is not valid', category='error')
        else:

            cur = g.db.cursor()
            cur.execute('select u.id as id, u.name as name from users u \
                        inner join user_lines ul on ul.user = u.id \
                        inner join user_line_types ult on ult.id = ul.type \
                        where ul.visible = 1 and ult.visible = 1 \
                        and ult.name = "email" and ul.value = %s limit 1', (email,))
            if cur.rowcount > 0:
                user = cur.fetchone()
                newpass = generate_password()
                cur.execute('update users set password = %s where id = %s', (newpass, user.id))
                g.db.commit()
                smtp = smtplib.SMTP(app.config['SMTPHOST'], 587)
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                mu = app.config['SMTPUSER']
                mp = app.config['SMTPPWD']
                smtp.login(mu, mp)
                m = Mailer(smtp, app.config['MAILFROM'])
                m.send_forgot_password(newpass, email, user)
                m.close()

            # ALWAYS show this message, otherwise some nefarious unknown kan
            # figure out what email addresses we have..
            flash('An email with information on how to reset your password has been sent', category='success')
            return redirect(url_for('.login'))

    return render_template('forgot_password.html', title='Forgot password', key=key)


@app.before_request
def before_request():
        g.db = MySQLdb.connect(
                    host=app.config['DBHOST'],
                    user=app.config['DBUSER'],
                    passwd=app.config['DBPWD'],
                    db=app.config['DBDB'],
                    cursorclass=MySQLdb.cursors.DictCursor
                )

@app.teardown_request
def teardown_request(exception):
        db = getattr(g, 'db', None)
        if db is not None:
            db.close()

@app.route('/')
def index():
        return redirect(url_for('.section'))

@app.route('/s')
@app.route('/s/<string:section>')
def section(section=None):
        if section is None:
            cur = g.db.cursor()
            cur.execute('select s.name, s.description from sections s')
            sections = cur.fetchall()
            return render_template('allsections.html', title='All sections', sections=sections)
        cur = g.db.cursor()
        cur.execute("select p.id as id, p.title as title, p.content as content, p.type as type, u.name as username, p.created as created from posts p \
                     inner join users u on u.id = p.user \
                     inner join sections s on s.id = p.section \
                     where s.name = %s and p.visible = 1", (section,))
        posts = []
        for row in cur.fetchall():
            p = Post()
            p.id = row.id
            p.title = row.title
            p.content = row.content
            p.type = row.type
            p.user = row.username
            p.created = row.created
            posts.append(p)

        cur.execute('select * from sections where name = %s', (section,))
        if cur.rowcount == 0:
            abort(404)
        sect = cur.fetchone()

        return render_template('sectionlist.html', title='Viewing section {0}'.format(section, sect.description), posts=posts, sect=sect)

@app.route('/p/<int:id>')
def post(id):
    cur = g.db.cursor()
    cur.execute("select p.id as id, p.title as title, p.content as content, \
                        p.type as type, u.name as name, p.created as created from posts p \
                 inner join users u on u.id = p.user \
                 where p.id = %s and p.visible = 1 limit 1", (id,))
    if cur.rowcount == 0:
        abort(404)
    p = Post()
    row = cur.fetchone()
    p.id = row.id
    p.title = row.title
    p.content = row.content
    p.type = row.type
    p.user = row.name
    p.created = row.created

    cur.execute('select c.id as id, c.content as content, c.created as created, c.parent as parent, \
                        u.name as username, c.depth as depth, (select count(*) from comments c2 where c2.lineage like concat(c.lineage, "%%") and c2.lineage<>c.lineage) as num_children \
                 from comments c inner join users u on u.id = c.user where c.post = %s order by c.lineage', (id,))
    p.comments = cur.fetchall()
    return render_template('post.html', title=p.title, post=p, key=get_form_key())

@app.route('/p/<int:id>/delete', methods=['POST'])
@login_required
def delete_post(id):
    key = get_form_key()

    cur = g.db.cursor()
    cur.execute('select * from posts where id = %s and visible = 1', (id,))

    if cur.rowcount == 0:
        abort(404)
    post = cur.fetchone()
    if post.user != current_user.id:
        abort(403)

    tok = request.form['csrftoken']
    if tok != key:
        abort(400)

    cur.execute('update posts set visible = 0 where id = %s', (id,))
    g.db.commit()
    flash('Post deleted successfully', category='success')

    return redirect(url_for('.index'))

@app.route('/p/<int:id>/edit', methods=['GET','POST'])
@login_required
def edit_post(id):
    key = get_form_key()

    cur = g.db.cursor()
    cur.execute('select * from posts where id = %s', (id,))

    if cur.rowcount == 0:
        abort(404)
    post = cur.fetchone()
    if post.user != current_user.id:
        abort(403)
    if post.type != 0:
        flash('You cannot edit this type of post', category='error')

    if request.method == 'POST':
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)
        content = request.form['content']
        if len(content) < app.config['MINCONTENTLEN']:
            flash('You need to flesh out the content a bit more', category='error')
        else:
            cur.execute('update posts set content = %s where id = %s', (content, id))
            g.db.commit()
            flash('Post edited', category='success')
            return redirect(url_for('.post', id=id))

    return render_template('edit_post.html', title='Edit post ' + post.title, post=post, key=key)

@app.route('/c/<int:comment>/edit', methods = ['POST'])
@login_required
def edit_comment(comment):
    key = get_form_key()
    tok = request.form['csrftoken']
    content = request.form['content']
    if key != tok:
        abort(400)
    pass

@app.route('/p/<int:postid>/comment', methods = ['POST'])
@login_required
def post_comment(postid, parent=0):
    key = get_form_key()
    tok = request.form['csrftoken']
    content = request.form['content']

    if key != tok:
        abort(400)

    if len(content) < app.config['MINCONTENTLEN']:
        flash('You need to flesh out your comment more')
        return redirect(url_for('.post', id=postid))

    commentid=0
    if parent > 0:
        cur = g.db.cursor()
        cur.execute('insert into comments (post, user, content, depth, lineage) values (%s, %s, %s, 0, (select lineage from comments wher id = %s limit 1))',
                     (postid, current_user.id, content, parent))
        cur.execute('select LAST_INSERT_ID() as l')
        commentid = cur.fetchone().l
        cur.execute('update comments set lineage = concat(lineage, "-", %s) where id = %s', (commentid, commentid))
        g.db.commit()
    else:
        cur = g.db.cursor()
        cur.execute('insert into comments (post, user, content, depth) values (%s, %s, %s, 0)',
                     (postid, current_user.id, content))
        cur.execute('select LAST_INSERT_ID() as l')
        commentid = cur.fetchone().l
        cur.execute('update comments set lineage = %s where id = %s', (commentid, commentid))
        g.db.commit()
    return redirect(url_for('.post', id=postid, _anchor='c' + str(commentid)))

@app.route('/u/<string:username>')
def user(username):
    cur = g.db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("select p.id as id, p.title as title, p.content as content, p.type as type, u.name as username, p.created as created from posts p \
                 inner join users u on u.id = p.user \
                 inner join sections s on s.id = p.section \
                 where p.visible = 1 and u.name = %s", (username,))
    posts = []
    for row in cur.fetchall():
        p = Post()
        p.id = row.id
        p.title = row.title
        p.content = row.content
        p.type = row.type
        p.user = row.username
        p.created = row.created
        posts.append(p)

    cur.execute("select * from users where name = %s limit 1", (username,))
    user = cur.fetchone()
    if current_user != None and current_user.is_authenticated():
        # A logged in user is viewing another users page
        if user.id == current_user.id:
            # A logged in user is viewing his own page
            pass
        pass

    return render_template('userpage.html', title='Posts made by ' + username, posts=posts, user=user)

@app.route('/s/<string:section>/post', methods=['GET','POST'])
@login_required
def newpost(section):
    cur = g.db.cursor()
    cur.execute("select s.id as id, s.name as name, s.description as description from sections s where s.name = %s", (section,))
    if cur.rowcount == 0:
        abort(404)

    row = cur.fetchone()
    sectionid = row.id
    sectionname = row.name
    sectiondescription = row.description
    key = get_form_key()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        link = request.form['link']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

        valid = True

        if not title.replace(' ', '0').isalnum():
            if valid: flash('Title can only contain alphanumeric characters and spaces', category='error')
            valid = False
        if len(content) < app.config['MINCONTENTLEN'] and len(link) < 3:
            if valid: flash('You need to flesh out the content more', category='error')
            valid = False

        if len(link) > 0:
            # Link post
            if link.startswith(app.config['ALLOWLINKS']):
                if valid:
                    cur.execute("insert into posts (section, type, title, content, user) values \
                            (%s, 1, %s, %s, %s)", (sectionid, title, link, current_user.id))
                    cur.execute("select LAST_INSERT_ID() as l")
                    postid = cur.fetchone().l
                    g.db.commit()
                    return redirect(url_for('.post', id=postid))
            else:
                if valid: flash('That does not look like a proper link. Please add either http:// or https:// to the link', category='error')
                valid = False
        else:
            if valid:
                cur.execute("insert into posts (section, type, title, content, user) values \
                            (%s, 0, %s, %s, %s)", (sectionid, title, content, current_user.id))
                cur.execute("select LAST_INSERT_ID() as l")
                postid = cur.fetchone().l
                g.db.commit()
                return redirect(url_for('.post', id=postid))

    return render_template('new_post.html', title="Create a new post in /s/" + section, key=key)

@app.route('/new_section', methods=['GET', 'POST'])
@login_required
def newsection():
    key = get_form_key()
    if request.method == 'POST':
        s = request.form['section'].lower()
        d = request.form['description']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

        valid = True
        if s == 'conspiracy':
            flash("It's not going to be that easy...", category='error')
            valid=False
        if not s.replace('_', '1').replace('-', '1').isalnum():
            if valid: flash("Invalid name section name. Only alphanumeric characters , '_' and, '-' are accepted", category='error')
            valid = False
        if len(d) < 16:
            flash("At least provide a bit of a description. How fun is it with a section about nothing?", category='error')
            valid=False

        if valid:
            cur = g.db.cursor()
            cur.execute("select * from sections where name = %s ", (s,))
            if cur.rowcount > 0:
                flash('Section already exists', category='error')
            else:
                cur.execute('insert into sections (name, description) values (%s, %s)', (s, d))
                g.db.commit()
                flash('Section created successfully. Welcome to your new kingdom', category='success')
                return redirect(url_for('.section', section=s))

    return render_template('new_section.html', title='Create a new section', key=key);

@app.route('/favicon.ico')
def favicon():
	return send_from_directory(os.path.join(app.root_path, 'static'),
			'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html', title='Not found'), 404

@app.errorhandler(400)
def error400(e):
    return render_template('400.html', title='Invalid request', what='Your browser and the web server doesn\'t seem to get along'), 400

@app.errorhandler(403)
def error403(e):
    return render_template('400.html', title='Not allowed', what='You are trying to perform an action that just isnt allowed'), 403

@app.errorhandler(501)
def error501(e):
    return render_template('500.html', title='We are planning on having that feature, just not yet.'), 501

@app.errorhandler(500)
def server_error(e):
    return render_template('500.html', title='Something has gone wrong'), 500

"""
@app.errorhandler(Exception)
def defaultHandler(e):
    return render_template('500.html', title='Some programmer has made an assumption that just wasn\'t valid.'), 500
"""

if __name__ == "__main__":
        app.run(host='0.0.0.0')
