from flask import Flask, current_app, render_template, flash, redirect, url_for, session, request, g, logging, send_from_directory, Markup

from datetime import datetime
from wtforms import StringField, TextAreaField, BooleanField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
# Cryptography
import scrypt
#Upload
from os import path, remove, stat, environ, urandom
import glob
from werkzeug.utils import secure_filename
from flask_gravatar import Gravatar
# Email confirmation 'emailToken.py'
from flask_mail import Mail
import emailToken
# Transactions
# import transaction
from dotenv import load_dotenv
import braintree
# Forgot Password
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

app = Flask(__name__)
app.config.from_pyfile('config.py')

mail = Mail(app)

from decorators import is_logged_in, is_admin, is_allowed_edit, anonymous_user_required
from db import get_db, close_connection, insert, update, query_db

dotenv_path = 'mycred.env'
load_dotenv(dotenv_path)

braintree.Configuration.configure(
	environ.get('BT_ENVIRONMENT'),
	environ.get('BT_MERCHANT_ID'),
	environ.get('BT_PUBLIC_KEY'),
	environ.get('BT_PRIVATE_KEY')
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

braintree.Configuration.configure(braintree.Environment.Sandbox,
				  merchant_id="ykqfttjmkjxqh34f",
				  public_key="qznsjn6yymz2b35y",
				  private_key="7920b35f630e2c714320dee79cbcd8dd")


#Generate token
@app.route("/client_token", methods=["GET"])
@is_logged_in
def client_token():
	return braintree.ClientToken.generate()

@app.route("/checkout", methods=["POST"])
@is_logged_in
def create_purchase():
	nonce_from_the_client = request.form["payment_method_nonce"]
	#Use payment method nonce here...

@app.route('/checkouts/new', methods=['GET'])
@is_logged_in
def new_checkout():
	client_token = braintree.ClientToken.generate()
	return render_template('payment.html', client_token=client_token)

@app.route('/checkouts/<transaction_id>', methods=['GET'])
@is_logged_in
def show_checkout(transaction_id):
	transaction = braintree.Transaction.find(transaction_id)
	result = {}
	if transaction.status in TRANSACTION_SUCCESS_STATUSES:
		result = {
			'header': 'Sweet Success!',
			'icon': 'success',
			'message': 'Your test transaction has been successfully processed. See the Braintree API response and try again.'
		}
		update("users", ("status",), "id=?", ("ACTIVE", session['id']))
	
	else:
		result = {
			'header': 'Transaction Failed',
			'icon': 'fail',
			'message': 'Your test transaction has a status of ' + transaction.status + '. See the Braintree API response and try again.'
		}

	return render_template('show_payment.html', transaction=transaction, result=result)

@app.route('/checkouts', methods=['POST'])
@is_logged_in
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


directivaMemberList = ['president', 'vicepresident', 'treasurer', 'pragent', 'secretary', 'boardmember1', 'boardmember2']

gravatar = Gravatar(app,
					size=100,
					rating='g',
					default='retro',
					force_default=False,
					force_lower=False,
					use_ssl=False,
					base_url=None)


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

			fp = path.join(static_folder, filename)
			if path.exists(fp):
				values['_'] = int(stat(fp).st_mtime)
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
	# Check to redirect to transaction payment
	payNow = BooleanField("Pay Membership now?")

# User Register
@app.route('/register', methods=['GET', 'POST'])
@anonymous_user_required
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		email = str(form.email.data).lower()
		if email.endswith("@upr.edu"):
			studentID = str(form.studentID.data)
			phoneNumber = str(form.phoneNumber.data)
			# Check that student number, email and phone number are unique
			if len(query_db("SELECT id FROM users WHERE studentID = ?", [studentID])):
				flash('Student Number already taken.', 'danger')
			elif len(query_db("SELECT id FROM users WHERE email = ? and priviledge != 'ADMIN'", [email])):
				flash('Email address already taken.', 'danger')
			elif len(query_db("SELECT id FROM users WHERE phoneNumber = ?", [phoneNumber])):
				flash('Phone Number already taken.', 'danger')
			else:
				# Generate a random salt
				random_salt = urandom(64)
				# Encode the salt to store its hex value into the database
				salt = random_salt.encode('hex')
				# Generate the hash using the password and salt
				password = scrypt.hash(str(form.password.data), random_salt).encode('hex')
				# Store the values into variables to avoid repetition
				firstName = str(form.studentFirstName.data)
				lastName = str(form.studentLastName.data)
				
				# Insert the user into the database with all corresponding fields and return its table row id
				userID = insert("users", ("email", "studentID", "password", "salt", "studentFirstName", "studentLastName", "phoneNumber"), (email, studentID, password, salt, firstName, lastName, phoneNumber))
				
				# Generate and send the confirmation email
				token = emailToken.generate_confirmation_token(email)
				confirm_url = url_for('confirm_email', token=token, _external=True)
				html = render_template('activate.html', confirm_url=confirm_url)
				subject = "Please confirm your email"
				emailToken.send_email(email, subject, html)
				# Flash the user with a successful registration and login. Remind to verify email address.
				flash('You are now registered and logged in. A confirmation email has been sent to verify your account.', 'success')
				
				# Store all the necessary variables into the session to login
				session['id'] = userID
				session['logged_in'] = True
				session['username'] = firstName
				session['email'] = email
				session['customPicture'] = "FALSE"
				session['confirmation'] = 0
				session['admin'] = False

				# If user checked membership payment, redirect to new_checkout for transaction process.
				if form.payNow.data:
					return redirect(url_for('new_checkout'))
				# Else the user will be redirected to unconfirmed to be reminded about confirming email address.
				else:
					return redirect(url_for('unconfirmed'))
		# Flash the user with message indicating invalid UPR institutional email.
		else:
			flash('Email address must be a valid UPR institutional email.', 'danger')
	return render_template('register.html', form=form)

# User login
@app.route('/login', methods=['GET', 'POST'])
@anonymous_user_required
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
			password_candidate = str(request.form['password'])

			# Get user by username
			result = query_db("SELECT id,studentFirstName,email,password,salt,customPicture,confirmation,priviledge FROM users WHERE email = ? and priviledge != 'ADMIN'", (username,), True) if logging_with_email else query_db("SELECT id,studentFirstName,email,password,salt,customPicture,confirmation,priviledge FROM users WHERE studentID = ?", (username,), True)
			if result != None:
				# Get stored hash
				uni_salt = result['salt'].decode('hex')
				password = result['password'].decode('hex')
				# Compare Passwords
				if scrypt.hash(password_candidate, uni_salt) == password:
					# Passed
					session['logged_in'] = True
					session['username'] = result['studentFirstName']
					session['id'] = result['id']
					session['email'] = result['email']
					session['customPicture'] = result['customPicture']
					session['confirmation'] = result['confirmation']
					session['admin'] = True if result['priviledge'] == "ADMIN" else False

					#flash('You are now logged in', 'success')
					if session['admin']:
						return redirect(url_for('adminPanel'))
					return redirect(url_for('user_profile', id=session['id']))
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
			random_salt = urandom(64)
			new_salt = random_salt.encode('hex')
			new_password = scrypt.hash(str(password_submit_form.password.data), random_salt).encode('hex')
			
			update("users", ("password", "salt"), "id=? and priviledge != 'ADMIN'", (new_password, new_salt, verified_result))
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
			session['confirmation'] = 1
			flash('You have confirmed your account. Thanks!', 'success')
	else:
		return render_template('404.html')
	return redirect(url_for('index'))

@app.route('/unconfirmed')
@is_logged_in
def unconfirmed():
	if session['confirmation']:
		flash('Account already confirmed.', 'warning')
		return redirect(url_for('user_profile', id=session['id']))
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

@app.route('/admin')
@is_logged_in
@is_admin
def adminPanel():
	pendingMembers = query_db("SELECT id,studentFirstName,studentLastName,email,customPicture,status FROM users WHERE status != 'ACTIVE' and priviledge != 'ADMIN'")
	return render_template('admin.html', result=pendingMembers)

@app.route('/activate/<string:id>')
@is_logged_in
@is_admin
def activateMembership(id):
	result = query_db("SELECT status,studentFirstName,studentLastName FROM users WHERE id = ?", [id], True)
	if result:
		if result['status'] == "ACTIVE":
			flash(result['studentFirstName'] + " " + result['studentLastName'] + " is already an active member.", 'warning')
			return redirect(url_for('adminPanel'))
	else:
		flash('User does not exist.', 'danger')
		return redirect(url_for('adminPanel'))
	cur = get_db().cursor()
	cur.execute("UPDATE users SET status='ACTIVE' WHERE id=?",(id))
	get_db().commit()
	cur.close()
	flash(result['studentFirstName'] + " " + result['studentLastName'] + " is now a member!", "success")
	return redirect(url_for('adminPanel'))

@app.route('/suspend/<string:id>')
@is_logged_in
@is_admin
def suspendMembership(id, studentFirstName="", studentLastName=""):
	result = query_db("SELECT status,studentFirstName,studentLastName FROM users WHERE id = ?", [id], True)
	if result:
		if result['status'] == "SUSPENDED":
			flash(result['studentFirstName'] + " " + result['studentLastName'] + " is already suspended.", 'warning')
			return redirect(url_for('adminPanel'))
	else:
		flash('User does not exist.', 'danger')
		return redirect(url_for('adminPanel'))
	cur = get_db().cursor()
	cur.execute("UPDATE users SET status='SUSPENDED' WHERE id=?",(id))
	get_db().commit()
	cur.close()
	flash(result['studentFirstName'] + " " + result['studentLastName'] + " has been suspended!", "danger")
	return redirect(url_for('adminPanel'))

# === PROFILE === #

class AdminForm(FlaskForm):
	uploadFile = FileField("Upload Avatar", validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Images only!')])
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

class ProfileForm(FlaskForm):
	uploadFile = FileField("Upload Avatar", validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Images only!')])
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
def edit_profile(id):
	# Get profile by id
	result = query_db("SELECT studentFirstName,studentLastName,password,salt,email FROM users WHERE id = ?", [id], True)
	if result == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# If admin, get different form with admin email
	if session['id'] == int(id) and session['admin']:
		form = AdminForm(studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'], adminEmail=result['email'])
	# Else the user has the same id or the admin is in another users info
	else:
		form = ProfileForm(studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'])
	if request.method == 'POST' and form.validate_on_submit():
		# Admin can bypass password verification or user must match their password
		if session['id'] != int(id) or scrypt.hash(str(form.password.data), result['salt'].decode('hex')) == result['password'].decode('hex'):

			studentFirstName = str(form.studentFirstName.data)
			studentLastName = str(form.studentLastName.data)
			f = request.files['uploadFile']
			filename = secure_filename(f.filename)
			if filename != "":
				filename = secure_filename(f.filename)
				filename = str(id)+"."+str(filename.split('.')[-1])
				for img in glob.glob(app.config['UPLOAD_FOLDER'] + "/" + str(id)+".*"):
					if path.exists(img):
						remove(img)
				f.save(path.join(app.config['UPLOAD_FOLDER'], filename))
			if str(form.new_password.data) != "":
				random_salt = urandom(64)
				new_salt = random_salt.encode('hex')
				new_password = scrypt.hash(str(form.new_password.data), random_salt).encode('hex')
				# Update the database to include the new set parameters by the user
				if filename != "":
					update("users", ("studentFirstName", "studentLastName", "password", "salt", "customPicture"), "id=?", (studentFirstName, studentLastName, new_password, new_salt, filename, id))
				else:
					update("users", ("studentFirstName", "studentLastName", "password", "salt"), "id=?", (studentFirstName, studentLastName, new_password, new_salt, id))
			else:
				if filename != "":
					update("users", ("studentFirstName", "studentLastName", "customPicture"), "id=?", (studentFirstName, studentLastName, filename, id))
				else:
					update("users", ("studentFirstName", "studentLastName"), "id=?", (studentFirstName, studentLastName, id))
			# If admin is editing the profile, only change the session variables for the user
			if session['id'] == int(id):
				if session['admin'] and str(form.adminEmail.data) != "":
					update("users", ("email",), "id=?", (str(form.adminEmail.data).lower(), id))
				session['username'] = studentFirstName
				if filename != "":
					session['customPicture'] = filename
			flash('User profile modified', 'success')
		else:
			flash('Password is incorrect', 'danger')
		return redirect(url_for('edit_profile', id=id))
	return render_template('edit_profile.html', form=form, id=int(id))

@app.route('/user/<string:id>')
def user_profile(id):
	# Get post by id
	user = query_db("SELECT id,studentFirstName,studentLastName,email,biography,customPicture FROM users WHERE id = ?", (id,), True)
	# TODO: Query the courses taken by that user
	if user == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# Check if the profile page belongs to the admin
	isAdminAccount = query_db("SELECT email FROM users WHERE id=? and priviledge='ADMIN'", (id,), True)
	# If it does, redirect to the page of the user with the same email account
	if isAdminAccount:
		hasSameEmail = query_db("SELECT id FROM users WHERE email=? and priviledge!='ADMIN'", (isAdminAccount['email'],), True)
		if hasSameEmail:
			return redirect(url_for('user_profile', id=hasSameEmail['id']))
		else:
			flash('User does not exist in our database', 'danger')
			return render_template('404.html')
	# Check if the user is logged in and is their own profile page
	if 'logged_in' in session and session['id'] == int(id):
		# Check if the user's account is confirmed
		if not session['confirmation']:
			flash(Markup('Please confirm your account! Didn\'t get the email? <a href="'+url_for('resend_confirmation')+'">Resend</a>'), 'warning')
		return render_template('user_profile.html', user=user)
	return render_template('user_profile.html', user=user)


if __name__ == '__main__':
	app.run(debug=True)
