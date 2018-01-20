from flask import Flask, render_template, flash, redirect, url_for, session, request, g, logging, send_from_directory, abort
import sqlite3
from datetime import datetime
from wtforms import StringField, TextAreaField, BooleanField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from passlib.hash import sha256_crypt
from functools import wraps
#Upload
import os
import glob
from werkzeug.utils import secure_filename
from flask_gravatar import Gravatar
#Transactions
import braintree
#Cache
from nocache import nocache

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

DATABASE = 'database/database.db'

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

braintree.Configuration.configure(braintree.Environment.Sandbox,
                                  merchant_id="ykqfttjmkjxqh34f",
                                  public_key="qznsjn6yymz2b35y",
                                  private_key="7920b35f630e2c714320dee79cbcd8dd")

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

# Index
@app.route('/')
def index():
	return render_template('home.html')

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

# Members
@app.route('/members')
def members():
	results = query_db("SELECT id,studentFirstName,studentLastName,email,customPicture FROM users WHERE status = 'ACTIVE'")
	return render_template('members.html', results=results)


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
	# Prevent symbols in username
	studentID = StringField('Student Number', [validators.Regexp("\d{9}",message = "Enter a valid Student Number"),validators.DataRequired(), validators.Length(min=9, max=9)])

	email = EmailField('Email', [validators.DataRequired(), validators.Length(min=6, max=35), validators.Email()])
	studentFirstName = StringField('First Name', [validators.Regexp("\D",message = "Enter a valid First Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	studentLastName = StringField('Last Name', [validators.Regexp("\D",message = "Enter a valid Last Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	#
	phoneNumber = StringField('Phone Number', [validators.Regexp("\d{10}",message = "Enter Phone Number"),validators.DataRequired(), validators.Length(min=10, max=10)])
	# Add validators: At least 1 number, at least 1 uppercase
	password = PasswordField('Password', [
		validators.DataRequired(), validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('Confirm Password')
	#boolean Field
	#Here
	payNow = BooleanField("Pay Now")
	# validators.Optional(strip_whitespace=True)
	# validators.Regexp(regex= , flags= , message)

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		email = form.email.data.lower()
		if email.endswith("@upr.edu"):
			studentID = str(form.studentID.data)
			phoneNumber = str(form.phoneNumber.data)

			# Check that username and email are unique
			if len(query_db("SELECT id FROM users WHERE studentID = ?", [studentID])):
				flash('Student Number already taken.', 'danger')
			elif len(query_db("SELECT id FROM users WHERE email = ?", [email])):
				flash('Email address already taken.', 'danger')
			elif len(query_db("SELECT id FROM users WHERE phoneNumber = ?", [phoneNumber])):
				flash('Phone Number already taken.', 'danger')
			else:
				password = sha256_crypt.encrypt(str(form.password.data))
				firstName = form.studentFirstName.data
				lastName = form.studentLastName.data
				# Execute query
				paymentStatus = "ACTIVE" if form.payNow.data else "PENDING"
				insert("users", ("email", "studentID", "password", "studentFirstName", "studentLastName", "phoneNumber", "status", "date_created"), (email, studentID, password, firstName, lastName, phoneNumber, paymentStatus, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
				flash('You are now registered and can log in.', 'success')
				return redirect(url_for('index'))
		else:
			flash('Email address must be a valid UPR institutional email.', 'danger')
	return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		logging_with_email = False
		validCredentials = False
		# Get Form Fields
		studentID = str(request.form['username'])
		if studentID.endswith("@upr.edu"):
			logging_with_email = True
			validCredentials = True
		elif not studentID.isdigit():
			flash("Invalid username or password.", 'danger')
		else:
			validCredentials = True
		if validCredentials:
			password_candidate = request.form['password']

			# Get user by username
			result = query_db("SELECT id,studentFirstName,email,password,customPicture FROM users WHERE email = ?", (studentID,), True) if logging_with_email else query_db("SELECT id,studentFirstName,email,password,customPicture FROM users WHERE studentID = ?", (studentID,), True)
			if result != None:
				# Get stored hash
				password = result['password']

				# Compare Passwords
				if sha256_crypt.verify(password_candidate, password):
					# Passed
					session['logged_in'] = True
					session['username'] = result['studentFirstName']
					session['id'] = result['id']
					session['email'] = result['email']
					session['customPicture'] = result['customPicture']

					flash('You are now logged in', 'success')
					return redirect(url_for('dashboard'))
				else:
					flash("Invalid username or password.", 'danger')
					#error = 'Username and/or Password is incorrect'
					#return render_template('login.html', error=error)
				# Close connection
			else:
				flash("Invalid username or password.", 'danger')
				#error = 'Username and/or Password is incorrect'
				#return render_template('login.html', error=error)

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

def is_admin(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'ADMIN' in query_db("SELECT priviledge FROM users WHERE id=?", [session['id']], True):
			return f(*args, **kwargs)
		else:
			flash('Unauthorized: You do not have sufficient priviledges.', 'danger')
			return redirect(url_for('login'))
	return wrap

def is_allowed_edit(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'ADMIN' in query_db("SELECT priviledge FROM users WHERE id=?", [session['id']], True) or str(kwargs['id']) == str(session['id']):
			return f(*args, **kwargs)
		else:
			flash('Unauthorized: Attempting to modify information from other user.', 'danger')
			return redirect(url_for('dashboard'))
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
	result = query_db("SELECT * FROM posts")

	if result != None:
		return render_template('dashboard.html', articles=[articles for articles in result])
	else:
		msg = 'No Articles Found'
		return render_template('dashboard.html', msg=msg)

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
	uploadFile = FileField("Upload Avatar")
	studentFirstName = StringField('First Name', [validators.Length(min=1,max=25)])
	studentLastName = StringField('Last Name', [validators.Length(min=1,max=25)])
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
@is_allowed_edit
@nocache
def edit_profile(id):
	# Get post by id
	# TODO CAMBIAR EL QUERY PA QUE NO COJA TO
	result = query_db("SELECT * FROM users WHERE id = ?", [id], True)
	if result == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# Get form
	form = ProfileForm(request.form, studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'])
	if request.method == 'POST' and form.validate_on_submit():
		if sha256_crypt.verify(form.password.data, result['password']):
			studentFirstName = form.studentFirstName.data
			studentLastName = form.studentLastName.data
			f = request.files['uploadFile']
			if f != None:		
				filename = secure_filename(f.filename)
				filename = str(id)+"."+str(filename.split('.')[-1])
				for img in glob.glob(app.config['UPLOAD_FOLDER'] + "/" + str(id)+".*"):
					if os.path.exists(img):
						os.remove(img)
				f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			cur = get_db().cursor()
			if form.new_password.data != "":
				new_password = sha256_crypt.encrypt(str(form.new_password.data))
				#Execute
				if f != None:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, password=?, customPicture=? WHERE id=?",(studentFirstName, studentLastName, new_password, filename, id))
					session['customPicture'] = filename
				else:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, password=? WHERE id=?",(studentFirstName, studentLastName, new_password, id))
			else:
				if f != None:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, customPicture=? WHERE id=?",(studentFirstName, studentLastName, filename, id))
					session['customPicture'] = filename
				else:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=? WHERE id=?",(studentFirstName, studentLastName, id))				

			session['username'] = studentFirstName
			# Commit to DB
			get_db().commit()
			#Close connection
			cur.close()
			flash('User profile modified', 'success')
		else:
			flash('Password is incorrect', 'danger')
		return redirect(url_for('edit_profile', id=id))
	return render_template('edit_profile.html', form=form)

@app.route('/user/<string:id>')
def user_profile(id):
	# Get post by id
	user = query_db("SELECT studentFirstName,studentLastName,email,biography,customPicture FROM users WHERE id = ?", [id], True)
	# TODO: Query the courses taken by that user
	if user == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	return render_template('user_profile.html', user=user)

# class TagListField(Field):
#     widget = TextInput()
#     def _value(self):
#         if self.data:
#             return u', '.join(self.data)
#         else:
#             return u''
#     def process_formdata(self, valuelist):
#         if valuelist:
#             self.data = [x.strip() for x in valuelist[0].split(',')]
#         else:
#             self.data = []

# Article Form Class
class PostForm(FlaskForm):
	title = StringField('Title', [validators.Length(min=1, max=200)])
	body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_post', methods=['GET', 'POST'])
@is_logged_in
def add_post():
	form = PostForm(request.form)

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
	form = PostForm(request.form)

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

	flash('Post Deleted', 'success')

	return redirect(url_for('dashboard'))
	
#Generate token
@app.route("/client_token", methods=["GET"])
def client_token():
	return braintree.ClientToken.generate()

@app.route("/checkout", methods=["POST"])
def create_purchase():
	nonce_from_the_client = request.form["payment_method_nonce"]
	# Use payment method nonce here...

if __name__ == '__main__':
	app.secret_key='secret123'
	app.run(debug=True)
