from flask import Flask, current_app, render_template, flash, redirect, url_for, session, request, g, logging, send_from_directory, Markup
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
from os.path import join, dirname
from dotenv import load_dotenv
# Email confirmation 'emailToken.py'
import emailToken
from flask_mail import Mail
# Forgot Password
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

app = Flask(__name__)
app.config.from_pyfile('config.py')
dotenv_path = 'mycred.env'
load_dotenv(dotenv_path)
app.secret_key = os.environ.get('APP_SECRET_KEY')
mail = Mail(app)

braintree.Configuration.configure(
    os.environ.get('BT_ENVIRONMENT'),
    os.environ.get('BT_MERCHANT_ID'),
    os.environ.get('BT_PUBLIC_KEY'),
    os.environ.get('BT_PRIVATE_KEY')
)

TRANSACTION_SUCCESS_STATUSES = [
    braintree.Transaction.Status.Authorized,
    braintree.Transaction.Status.Authorizing,
    braintree.Transaction.Status.Settled,
    braintree.Transaction.Status.SettlementConfirmed,
    braintree.Transaction.Status.SettlementPending,
    braintree.Transaction.Status.Settling,
    braintree.Transaction.Status.SubmittedForSettlement
]

directivaMemberList = ['president', 'vicepresident', 'secretary', 'treasurer', 'publicrelationist' , 'vocal1', 'vocal2', 'vocal3']
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

# === Fixing cached static files in Flask ===
# https://gist.github.com/Ostrovski/f16779933ceee3a9d181
@app.url_defaults
def hashed_static_file(endpoint, values):
	if 'static' == endpoint or endpoint.endswith('.static'):
		filename = values.get('filename')
		if filename:
			blueprint = request.blueprint
			if '.' in endpoint:  # blueprint
				blueprint = endpoint.rsplit('.', 1)[0]

			static_folder = app.static_folder
		   # use blueprint, but dont set `static_folder` option
			if blueprint and app.blueprints[blueprint].static_folder:
				static_folder = app.blueprints[blueprint].static_folder

			fp = os.path.join(static_folder, filename)
			if os.path.exists(fp):
				values['_'] = int(os.stat(fp).st_mtime)
# === Fixing cached static files in Flask ===

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

# Members
@app.route('/about')
def about():
	directivaMembers = query_db("SELECT studentID,studentFirstName,studentLastName,customPicture FROM users WHERE priviledge = 'ADMIN'")
	return render_template('about.html', directiva=directivaMembers)


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

	email = EmailField('Email', [validators.DataRequired(), validators.Length(min=10, max=35), validators.Email()])
	studentFirstName = StringField('First Name', [validators.Regexp("\D",message = "Enter a valid First Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	studentLastName = StringField('Last Name', [validators.Regexp("\D",message = "Enter a valid Last Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	phoneNumber = StringField('Phone Number', [validators.Regexp("\d{10}",message = "Enter Phone Number"),validators.DataRequired(), validators.Length(min=10, max=10)])
	# Add validators: At least 1 number, at least 1 uppercase
	password = PasswordField('Password', [
		validators.DataRequired(), validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('Confirm Password')
	#boolean Field
	#Here
	payNow = BooleanField("Pay Membership now?")
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
			elif len(query_db("SELECT id FROM users WHERE email = ? and priviledge != 'ADMIN'", [email])):
				flash('Email address already taken.', 'danger')
			elif len(query_db("SELECT id FROM users WHERE phoneNumber = ?", [phoneNumber])):
				flash('Phone Number already taken.', 'danger')
			else:
				password = sha256_crypt.encrypt(str(form.password.data))
				firstName = form.studentFirstName.data
				lastName = form.studentLastName.data
				# Execute query
				# Pay now
				if form.payNow.data:
					insert("users", ("email", "studentID", "password", "studentFirstName", "studentLastName", "phoneNumber", "status"), (email, studentID, password, firstName, lastName, phoneNumber, "ACTIVE"))
				else:
					insert("users", ("email", "studentID", "password", "studentFirstName", "studentLastName", "phoneNumber"), (email, studentID, password, firstName, lastName, phoneNumber))
				# Generate and Send the confirmation email
				token = emailToken.generate_confirmation_token(email)
				confirm_url = url_for('confirm_email', token=token, _external=True)
				html = render_template('activate.html', confirm_url=confirm_url)
				subject = "Please confirm your email"
				emailToken.send_email(email, subject, html)

				flash('You are now registered and logged in. A confirmation email has been sent to verify your account.', 'success')
				userID = query_db("SELECT id FROM users WHERE studentID=?", (studentID,), True)
				session['id'] = userID['id']
				session['logged_in'] = True
				session['username'] = firstName
				session['email'] = email
				session['customPicture'] = "FALSE"
				session['confirmation'] = 0
				session['admin'] = False
				return redirect(url_for('unconfirmed'))
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
		username = str(request.form['username']).lower()
		if username.endswith("@upr.edu"):
			if len(username) >= 10 and len(username) <= 35:
				logging_with_email = True
				validCredentials = True
		elif username.isdigit() or username in directivaMemberList:
			validCredentials = True
		if validCredentials:
			password_candidate = request.form['password']

			# Get user by username
			result = query_db("SELECT id,studentFirstName,email,password,customPicture,confirmation,priviledge FROM users WHERE email = ? and priviledge != 'ADMIN'", (username,), True) if logging_with_email else query_db("SELECT id,studentFirstName,email,password,customPicture,confirmation,priviledge FROM users WHERE studentID = ?", (username,), True)
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
					session['confirmation'] = result['confirmation']
					session['admin'] = True if result['priviledge'] == "ADMIN" else False

					#flash('You are now logged in', 'success')
					return redirect(url_for('dashboard'))
				else:
					flash("Invalid username or password.", 'danger')
					#error = 'Username and/or Password is incorrect'
					#return render_template('login.html', error=error)
			else:
				flash("Invalid username or password.", 'danger')
				#error = 'Username and/or Password is incorrect'
				#return render_template('login.html', error=error)
		else:
			flash("Invalid username or password.", 'danger')

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

def check_confirmed(func):
	@wraps(func)
	def decorated_function(*args, **kwargs):
		if not session['confirmation']:
			flash(Markup('Please confirm your account! Didn\'t get the email? <a href="/resend">Resend</a>'), 'warning')
			#flash('Please confirm your account! Didn\'t get the email?', 'warning')
		return func(*args, **kwargs)

	return decorated_function

# ==== Forgot Password ====
# https://navaspot.wordpress.com/2014/06/25/how-to-implement-forgot-password-feature-in-flask/
class ExistingUser(object):
	def __init__(self, message="Email doesn't exists"):
		self.message = message
	def __call__(self, form, field):
		if not query_db("SELECT id FROM users WHERE email=? and priviledge != 'ADMIN'", (field.data,), True):
			raise ValidationError(self.message)

class ResetPassword(FlaskForm):
	email = EmailField('Email', validators=[validators.Required(),
		  validators.Email(),
		  ExistingUser(message='Email address is not available')
		 ])

class ResetPasswordSubmit(FlaskForm):
	# TODO Add password custom validator
	# password = PasswordField('Password', validators=custom_validators['edit_password'])
	password = PasswordField('Password', [validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match')])
	confirm = PasswordField('Confirm Password')

def get_token(id, expiration=1800):
		s = Serializer(app.config['SECRET_KEY'], expiration)
		return s.dumps({'user': id}).decode('utf-8')

#@staticmethod
# TODO Mejorar la seguridad de esto
def verify_token(token):
	s = Serializer(app.config['SECRET_KEY'])
	try:
		data = s.loads(token)
	except:
		return None
	id = data.get('user')
	if id:
		return id
	return None

def anonymous_user_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' not in session:
			return f(*args, **kwargs)
		else:
			flash('Logout to reset your password.', 'danger')
			return redirect(url_for('dashboard'))
	return wrap

@app.route('/reset-password', methods=['GET', 'POST'])
@anonymous_user_required
def forgot_password():
	token = request.args.get('token',None)
	form = ResetPassword(request.form) #form
	if form.validate_on_submit():
		email = form.email.data
		user = query_db("SELECT id FROM users WHERE email=? and priviledge != 'ADMIN'", (email,), True)
		if user:
			token = get_token(user['id'])
			confirm_url = url_for('reset_password', token=token, _external=True)
			html = render_template('reset_email.html', confirm_url=confirm_url)
			subject = "Password Reset for AECC"
			emailToken.send_email(email, subject, html)
			flash('A password reset email has been sent.', 'success')
	return render_template('forgot_password.html', form=form)

@app.route('/users/reset/<token>', methods=['GET', 'POST'])
@anonymous_user_required
def reset_password(token):
	verified_result = verify_token(token)
	if token and verified_result:
		password_submit_form = ResetPasswordSubmit(request.form)
		if password_submit_form.validate_on_submit():
			new_password = sha256_crypt.encrypt(str(password_submit_form.password.data))
			cur = get_db().cursor()
			cur.execute("UPDATE users SET password=? WHERE id=? and priviledge != 'ADMIN'",(new_password, verified_result))
			# Commit to DB
			get_db().commit()
			#Close connection
			cur.close()
			#return "password updated successfully"
			flash('Password updated successfully', 'success')
			return redirect(url_for('login'))
		return render_template("reset_password.html", form=password_submit_form)
	return render_template('404.html')

# Email Confirmation
@app.route('/confirm/<token>')
@is_logged_in
def confirm_email(token):
	try:
		email = emailToken.confirm_token(token)
	except:
		flash('The confirmation link is invalid or has expired.', 'danger')
	user = query_db("SELECT confirmation,confirmed_on FROM users WHERE email=? and priviledge != 'ADMIN'", (email,), True)
	if user != None:
		if user['confirmation']:
			flash('Your account is already confirmed', 'success')
		else:
			cur = get_db().cursor()
				
			cur.execute("UPDATE users SET confirmation=?, confirmed_on=? WHERE email=?",(1, datetime.now(), email))
			# Commit to DB
			get_db().commit()
			#Close connection
			cur.close()
			flash('You have confirmed your account. Thanks!', 'success')
	else:
		return render_template('404.html')
	return redirect(url_for('index'))

@app.route('/unconfirmed')
@is_logged_in
def unconfirmed():
	if session['confirmation']:
		return redirect(url_for('dashboard'))
	flash('Please confirm your account!', 'warning')
	return render_template('unconfirmed.html')

@app.route('/resend')
@is_logged_in
def resend_confirmation():
	token = emailToken.generate_confirmation_token(session['email'])
	confirm_url = url_for('confirm_email', token=token, _external=True)
	html = render_template('activate.html', confirm_url=confirm_url)
	subject = "Please confirm your email"
	emailToken.send_email(session['email'], subject, html)
	flash('A new confirmation email has been sent.', 'success')
	return redirect(url_for('unconfirmed'))

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
@check_confirmed
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
	# Add regular expression to check if endswith('@upr.edu')
	adminEmail = EmailField('Administrative Email', [validators.Length(min=10, max=35), validators.Email()])
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
def edit_profile(id):
	# Get post by id
	# TODO CAMBIAR EL QUERY PA QUE NO COJA TO
	result = query_db("SELECT studentFirstName,studentLastName,password,email FROM users WHERE id = ?", [id], True)
	if result == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# Get form
	if session['id'] == int(id) and session['admin']:
		form = ProfileForm(request.form, studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'], adminEmail=result['email'])
	else:
		form = ProfileForm(request.form, studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'])
	if request.method == 'POST' and form.validate_on_submit():
		# Admin can bypass password verification or user must match their password
		if session['id'] != int(id) or sha256_crypt.verify(form.password.data, result['password']):
			studentFirstName = form.studentFirstName.data
			studentLastName = form.studentLastName.data
			f = request.files['uploadFile']
			filename = secure_filename(f.filename)
			if filename != "":
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
				if filename != "":
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, password=?, customPicture=? WHERE id=?",(studentFirstName, studentLastName, new_password, filename, id))
				else:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, password=? WHERE id=?",(studentFirstName, studentLastName, new_password, id))
			else:
				if filename != "":
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=?, customPicture=? WHERE id=?",(studentFirstName, studentLastName, filename, id))
				else:
					cur.execute("UPDATE users SET studentFirstName=?, studentLastName=? WHERE id=?",(studentFirstName, studentLastName, id))				
			# If admin is editing the profile, only change the session variables for the user
			if session['id'] == int(id):
				if session['admin'] and form.adminEmail.data != "":
					cur.execute("UPDATE users SET email=? WHERE id=?",(form.adminEmail.data, id))
				session['username'] = studentFirstName
				if filename != "":
					session['customPicture'] = filename
			# Commit to DB
			get_db().commit()
			#Close connection
			cur.close()
			flash('User profile modified', 'success')
		else:
			flash('Password is incorrect', 'danger')
		return redirect(url_for('edit_profile', id=id))
	return render_template('edit_profile.html', form=form, id=int(id))

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
#@app.route("/client_token", methods=["GET"])
#def client_token():
#	return braintree.ClientToken.generate()

#@app.route("/checkout", methods=["POST"])
#def create_purchase():
#	nonce_from_the_client = request.form["payment_method_nonce"]
	# Use payment method nonce here...

#@app.route('/checkouts/new', methods=['GET'])
#def new_checkout():
#    client_token = braintree.ClientToken.generate()
#    return render_template('checkouts/new.html', client_token=client_token)

#@app.route('/checkouts/<transaction_id>', methods=['GET'])
#def show_checkout(transaction_id):
 #   transaction = braintree.Transaction.find(transaction_id)
#    result = {}
#    if transaction.status in TRANSACTION_SUCCESS_STATUSES:
#        result = {
#            'header': 'Sweet Success!',
#            'icon': 'success',
#            'message': 'Your test transaction has been successfully processed. See the Braintree API response and try again.'
#        }
#    else:
#        result = {
#            'header': 'Transaction Failed',
#            'icon': 'fail',
#            'message': 'Your test transaction has a status of ' + transaction.status + '. See the Braintree API response and try again.'
#        }

#    return render_template('checkouts/show.html', transaction=transaction, result=result)

#@app.route('/checkouts', methods=['POST'])
#def create_checkout():
#    result = braintree.Transaction.sale({
#        'amount': request.form['amount'],
#        'payment_method_nonce': request.form['payment_method_nonce'],
#        'options': {
#            "submit_for_settlement": True
#        }
#    })

#    if result.is_success or result.transaction:
#        return redirect(url_for('show_checkout',transaction_id=result.transaction.id))
 #   else:
#        for x in result.errors.deep_errors: flash('Error: %s: %s' % (x.code, x.message))
#        return redirect(url_for('new_checkout'))


if __name__ == '__main__':
	ALLOW@app.route('/checkouts/new', methods=['GET'])
def new_checkout():
    client_token = braintree.ClientToken.generate()
    return render_template('checkouts/new.html', client_token=client_token)

@app.route('/checkouts/<transaction_id>', methods=['GET'])
def show_checkout(transaction_id):
    transaction = braintree.Transaction.find(transaction_id)
    result = {}
    if transaction.status in TRANSACTION_SUCCESS_STATUSES:
        result = {
            'header': 'Sweet Success!',
            'icon': 'success',
            'message': 'Your test transaction has been successfully processed. See the Braintree API response and try again.'
        }
    else:
        result = {
            'header': 'Transaction Failed',
            'icon': 'fail',
            'message': 'Your test transaction has a status of ' + transaction.status + '. See the Braintree API response and try again.'
        }

    return render_template('checkouts/show.html', transaction=transaction, result=result)

@app.route('/checkouts', methods=['POST'])
def create_checkout():
    result = braintree.Transaction.sale({
        'amount': request.form['amount'],
        'payment_method_nonce': request.form['payment_method_nonce'],
        'options': {
            "submit_for_settlement": True
        }
    })

    if result.is_success or result.transaction:
        return redirect(url_for('show_checkout',transaction_id=result.transaction.id))
    else:
        for x in result.errors.deep_errors: flash('Error: %s: %s' % (x.code, x.message))
        return redirect(url_for('new_checkout'))
ED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])
	app.run(debug=True)
