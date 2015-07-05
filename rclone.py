import MySQLdb
import datetime
import os
import base64
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, send_from_directory
from flask.ext.login import LoginManager, login_user, logout_user, login_required, current_user
from models.user import User
from models.post import Post

app = Flask(__name__)
app.secret_key='supersecret'

lm = LoginManager()
lm.session_protection = 'strong'
lm.init_app(app)

lm.login_view = 'login'

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

@lm.user_loader
def load_user(userid):
    cur = g.db.cursor()
    cur.execute('select id, name, created from users where id = %s limit 1', (userid,))
    u = User()
    r = cur.fetchall()[0]
    u.id = r[0]
    u.name = str(r[1])
    u.created=r[2]
    return u

@app.route('/logout')
def logout():
    logout_user()
    next = request.args.get('next')
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

        if not user.isalnum():
            flash('Username or password is not valid')
            valid=False
        if len(pwd) < 6:
            flash('Username or password is not valid')
            valid=False
        if current_user != None and current_user.is_authenticated():
            flash('Already logged in')
            valid=False

        if valid:
            cur = g.db.cursor()
            cur.execute("select id, name, created from users \
                         where name = %s and password = %s", (user, pwd))
            if cur.rowcount == 0:
                flash('Unknown user or wrong password')
                return render_template('login.html', title='login', key=key)

            u = User()
            r = cur.fetchall()[0]
            u.id = r[0]
            u.name = str(r[1])
            u.created=r[2]

            login_user(u)

            next = request.args.get('next')
            return redirect(next or url_for('index'))
    return render_template('login.html', title='login', key=key)

def email_valid(email):
    return '@' in email

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

        if not user.isalnum():
            flash('Username needs to be alphanumeric')
            valid = False
        if len(pwd) < 6:
            flash('Password needs at least 6 characters')
            valid = False
        if not email_valid(email):
            flash('Email address is not valid')
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
                    abort(400)

                u = User()
                r = cur.fetchall()[0]
                u.id = r[0]
                u.name = str(r[1])
                u.created=r[2]

                login_user(u)
                g.db.commit()
            else:
                flash('Username taken')

    return render_template('new_login.html', title='create user', key=key)


@app.before_request
def before_request():
        g.db = MySQLdb.connect(
                    host='***REMOVED***',
                    user='rclone',
                    passwd='dummy',
                    db='rclone'
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
            cur = g.db.cursor(MySQLdb.cursors.DictCursor)
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
            p.id = row[0]
            p.title = row[1]
            p.content = row[2]
            p.type = row[3]
            p.user = row[4]
            p.created = row[5]
            posts.append(p)

        return render_template('sectionlist.html', title=section, posts=posts)

@app.route('/p/<int:id>')
def post(id):
    cur = g.db.cursor()
    cur.execute("select p.id, p.title, p.content, p.type, u.name, p.created from posts p \
                 inner join users u on u.id = p.user \
                 where p.id = %s and p.visible = 1 limit 1", (id,))
    if cur.rowcount == 0:
        abort(404)
    p = Post()
    row = cur.fetchall()[0]
    p.id = row[0]
    p.title = row[1]
    p.content = row[2]
    p.type = row[3]
    p.user = row[4]
    p.created = row[5]
    return render_template('post.html', title=p.title, post=p)

@app.route('/p/<int:id>/delete', methods=['POST'])
@login_required
def delete_post(id):
    key = get_form_key()

    cur = g.db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select * from posts where id = %s and visible = 1', (id,))

    if cur.rowcount == 0:
        abort(404)
    post = AttrDict(cur.fetchall()[0])
    if post.user != current_user.id:
        abort(403)

    tok = request.form['csrftoken']
    if tok != key:
        abort(400)

    cur.execute('update posts set visible = 0 where id = %s', (id,))
    g.db.commit()
    flash('Post deleted successfully')

    return redirect(url_for('.index'))

@app.route('/p/<int:id>/edit', methods=['GET','POST'])
@login_required
def edit_post(id):
    key = get_form_key()

    cur = g.db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute('select * from posts where id = %s', (id,))

    if cur.rowcount == 0:
        abort(404)
    post = AttrDict(cur.fetchall()[0])
    if post.user != current_user.id:
        abort(403)
    if post.type != 0:
        flash('You cannot edit this type of post')
        abort(403)

    if request.method == 'POST':
        user = request.form['username']
        pwd = request.form['password']
        email = request.form['email']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

    return render_template('edit_post.html', title='Edit post ' + post.title, post=post, key=key)

@app.route('/u/<string:username>')
def user(username):
    cur = g.db.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("select p.id as id, p.title as title, p.content as content, p.type as type, u.name as username, p.created as created from posts p \
                 inner join users u on u.id = p.user \
                 inner join sections s on s.id = p.section \
                 where p.visible = 1 and u.name = %s", (username,))
    posts = []
    for row in (AttrDict(d) for d in cur.fetchall()):
        p = Post()
        p.id = row.id
        p.title = row.title
        p.content = row.content
        p.type = row.type
        p.user = row.username
        p.created = row.created
        posts.append(p)

    cur.execute("select * from users where name = %s limit 1", (username,))
    user = AttrDict(cur.fetchall()[0])
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
    cur.execute("select s.id, s.name, s.description from sections s where s.name = %s", (section,))
    if cur.rowcount == 0:
        abort(404)

    row = cur.fetchall()[0]
    sectionid = row[0]
    sectionname = row[1]
    sectiondescription = row[2]

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        link = request.form['link']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

        if not title.replace(' ', '0').isalnum():
            abort(400)
        if len(content) < 16 and len(link) < 3:
            abort(400)

        if len(link) > 0:
            # Link post
            if link.startswith(('http://', 'https://')):
                cur.execute("insert into posts (section, type, title, content, user) values \
                         (%s, 1, %s, %s, %s)", (sectionid, title, link, current_user.id))
                cur.execute("select LAST_INSERT_ID()")
                postid = cur.fetchall()[0][0]
                g.db.commit()
                return redirect(url_for('.post', id=postid))
            else:
                abort(400)
        else:
            cur.execute("insert into posts (section, type, title, content, user) values \
                        (%s, 0, %s, %s, %s)", (sectionid, title, content, current_user.id))
            cur.execute("select LAST_INSERT_ID()")
            postid = cur.fetchall()[0][0]
            g.db.commit()
            return redirect(url_for('.post', id=postid))

    return render_template('new_post.html', title="Create a new post in /s/" + section)

@app.route('/new_section', methods=['GET', 'POST'])
@login_required
def newsection():
    key = get_form_key()
    if request.method == 'POST':
        s = request.form['section']
        d = request.form['description']
        tok = request.form['csrftoken']
        if tok != key:
            abort(400)

        valid = True
        if not s.replace('_', '1').replace('-', '1').isalnum():
            flash('Invalid name')
            valid = False

        if valid:
            cur = g.db.cursor()
            cur.execute("select * from sections where name = %s ", (s,))
            if cur.rowcount > 0:
                flash('Section already exists')
            else:
                cur.execute('insert into sections (name, description) values (%s, %s)', (s, d))
                g.db.commit()
                return redirect(url_for('.section', section=s))

    return render_template('new_section.html', title='Create a new section', key=key);

@app.route('/favicon.ico')
def favicon():
	return send_from_directory(os.path.join(app.root_path, 'static'),
			'favicon.ico', mimetype='image/vnd.microsoft.icon')

if __name__ == "__main__":
        app.debug=True
        app.run(host='0.0.0.0')
