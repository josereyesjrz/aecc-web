from flask import Flask, render_template, flash, redirect, url_for, session, request, g, logging, send_from_directory
import sqlite3
from datetime import datetime
from wtforms import StringField, TextAreaField, PasswordField, validators
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from passlib.hash import sha256_crypt
from functools import wraps
#Upload
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

DATABASE = 'database/database.db'


def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DATABASE)
		db.row_factory = sqlite3.Row
	return db

@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()

def insert(table, fields=(), values=()):
	# g.db is the database connection
	cur = get_db().cursor()
	query = 'INSERT INTO %s (%s) VALUES (%s)' % (
		table,
		', '.join(fields),
		', '.join(['?'] * len(values))
	)
	cur.execute(query, values)
	get_db().commit()
	id = cur.lastrowid
	cur.close()
	return id

def query_db(query, args=(), one=False):
	cur = get_db().execute(query, args)
	rv = cur.fetchall()
	cur.close()
	return (rv[0] if rv else None) if one else rv

#Articles = Articles()

# Index
@app.route('/')
def index():
	return render_template('home.html')

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

# About
@app.route('/about')
def about():
	return render_template('about.html')


# Articles
@app.route('/posts')
def posts():
	# Create cursor
	result = query_db("SELECT * FROM posts")

	if result != None:
		return render_template('posts.html', articles=[articles for articles in result])
	else:
		msg = 'No Posts Found'
		return render_template('posts.html', msg=msg)


#Single Article
@app.route('/posts/<string:id>/')
def post(id):
	result = query_db("SELECT * FROM posts WHERE id = %s", (id,), True)
	if result != None:
		return render_template('post.html', article=result)
	else:
		return 

# Register Form Class
class RegisterForm(FlaskForm):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('Confirm Password')
	upload = FileField("Upload Avatar")

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate_on_submit():
		name = form.name.data
		email = form.email.data
		username = form.username.data
		password = sha256_crypt.encrypt(str(form.password.data))
		f = request.files['upload']
		if f != None:
			filename = secure_filename(f.filename)
			f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
		else:
			filename = "icon-default.jpg"
		# Execute query
		insert("users", ("name", "email", "username", "password", "user_image", "date_created"), (name, email, username, password, filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

		flash('You are now registered and can log in', 'success')

		return redirect(url_for('login'))
	return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		# Get Form Fields
		username = request.form['username']
		password_candidate = request.form['password']

		# Get user by username
		result = query_db("SELECT * FROM users WHERE username = ?", (username,), True)
		if result != None:
			# Get stored hash
			password = result['password']

			# Compare Passwords
			if sha256_crypt.verify(password_candidate, password):
				# Passed
				session['logged_in'] = True
				session['username'] = username
				session['id'] = result['id']

				flash('You are now logged in', 'success')
				return redirect(url_for('dashboard'))
			else:
				error = 'Username and/or Password is incorrect'
				return render_template('login.html', error=error)
			# Close connection
		else:
			error = 'Username and/or Password is incorrect'
			return render_template('login.html', error=error)

	return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Unauthorized, Please login', 'danger')
			return redirect(url_for('login'))
	return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
	session.clear()
	flash('You are now logged out', 'success')
	return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():

	# Get articles
	userImage = query_db("SELECT user_image FROM users WHERE id=?", (session['id'],), True)
	result = query_db("SELECT * FROM posts")

	if result != None:
		return render_template('dashboard.html', articles=[articles for articles in result], userImage=userImage['user_image'])
	else:
		msg = 'No Articles Found'
		return render_template('dashboard.html', msg=msg, userImage=userImage['user_image'])

# === UPLOADS === #

@app.route('/uploads/<filename>')
def uploaded_file(filename):
	return send_from_directory(app.config['UPLOAD_FOLDER'],
							   filename)

def allowed_file(filename):
	return '.' in filename and \
		   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# === PROFILE === #

class ProfileForm(FlaskForm):
	name = StringField('Name', [validators.Length(min=1, max=50)])
	username = StringField('Username', [validators.Length(min=4, max=25)])
	email = StringField('Email', [validators.Length(min=6, max=50)])
	password = PasswordField('Current Password', [
		validators.DataRequired()
	])
	new_password = PasswordField('New Password', [
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('Confirm Password')


#Edit profile
@app.route('/edit_profile/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_profile(id):
	if str(id) == str(session['id']):
		# Get post by id
		result = query_db("SELECT * FROM users WHERE id = ?", (id,), True)
		# Get form
		form = ProfileForm(request.form, name=result['name'], username=result['username'], email=result['email'])
		if request.method == 'POST' and form.validate():
			if sha256_crypt.verify(form.password.data, result['password']):
				name = form.name.data
				email = form.email.data
				username = form.username.data
				cur = get_db().cursor()
				if form.new_password.data != "":
					new_password = sha256_crypt.encrypt(str(form.new_password.data))
					# Execute
					cur.execute("UPDATE users SET name=?, email=?, username=?, password=? WHERE id=?",(name, email, username, new_password, id))
				else:
					cur.execute("UPDATE users SET name=?, email=?, username=? WHERE id=?",(name, email, username, id))
				# Commit to DB
				get_db().commit()
				#Close connection
				cur.close()
				flash('User profile modified', 'success')
			else:
				flash('Password is incorrect', 'danger')
	else:
		flash('Unauthorized: Attempting to modify information from other user.', 'danger')
		return redirect(url_for('dashboard'))
	return render_template('edit_profile.html', form=form)

# Article Form Class
class ArticleForm(FlaskForm):
	title = StringField('Title', [validators.Length(min=1, max=200)])
	body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_post', methods=['GET', 'POST'])
@is_logged_in
def add_post():
	form = ArticleForm(request.form)
	if request.method == 'POST' and form.validate():
		title = form.title.data
		body = form.body.data

		# Execute
		insert("posts", ("title","author_id","body","date_created"), (title,session['id'],body,datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

		flash('Article Created', 'success')

		return redirect(url_for('dashboard'))

	return render_template('add_post.html', form=form)


# Edit Article
@app.route('/edit_post/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_post(id):

	# Get post by id
	result = query_db("SELECT * FROM posts WHERE id = ?", (id,), True)

	# Get form
	form = ArticleForm(request.form)

	# Populate article form fields
	form.title.data = result['title']
	form.body.data = result['body']

	if request.method == 'POST' and form.validate():
		title = request.form['title']
		body = request.form['body']

		cur = get_db().cursor()

		app.logger.info(title)

		# Execute
		cur.execute ("UPDATE posts SET title=?, body=? WHERE id=?",(title, body, id))
		# Commit to DB
		get_db().commit()

		#Close connection
		cur.close()

		flash('Article Updated', 'success')

		return redirect(url_for('dashboard'))

	return render_template('edit_post.html', form=form)

# Delete Article
@app.route('/delete_post/<string:id>', methods=['POST'])
@is_logged_in
def delete_post(id):
	# Create cursor
	cur = get_db().cursor()

	# Execute
	cur.execute("DELETE FROM posts WHERE id = ?", (id,))

	# Commit to DB
	get_db().commit()

	#Close connection
	cur.close()

	flash('Article Deleted', 'success')

	return redirect(url_for('dashboard'))

if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True)