from flask import Flask, current_app, render_template, flash, redirect, url_for, session, request, g, logging, Markup
from datetime import datetime
# Cryptography
import scrypt
# Upload
from os import path, remove, stat, environ, urandom, makedirs, listdir
from shutil import copy2
import glob
from werkzeug.utils import secure_filename
from flask_gravatar import Gravatar
# Email confirmation 'emailToken.py'
from flask_mail import Mail
import emailToken
# Transactions
from dotenv import load_dotenv
import braintree
# Forgot Password
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

app = Flask(__name__)
app.config.from_pyfile('config.py')

mail = Mail(app)

from decorators import is_logged_in, is_admin, is_allowed_edit, anonymous_user_required
from db import get_db, close_connection, insert, update, delete, query_db
from forms import RegisterForm, AdminForm, ProfileForm, EventForm, ResetPassword, ResetPasswordSubmit

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

#Generate token
@app.route("/client-token", methods=["GET"])
@is_logged_in
def client_token():
	return braintree.ClientToken.generate()

@app.route('/checkouts/new', methods=['GET'])
@is_logged_in
def new_checkout():
	client_token = braintree.ClientToken.generate()
	return render_template('payment.html', client_token=client_token)

@app.route('/checkouts/<transaction_id>', methods=['GET'])
@is_logged_in
def show_checkout(transaction_id):
	user = query_db("SELECT email, studentFirstName, studentLastName FROM users WHERE id=? and priviledge != 'ADMIN'", (session['id'],), True)
	# Get the transaction information by its id
	transaction = braintree.Transaction.find(transaction_id)
	result = {}
	# Check the transaction status to see if it was successfully processed.
	if transaction.status in TRANSACTION_SUCCESS_STATUSES:
		result = {
			'header': 'Payment has been process',
			'icon': 'success',
			'message': 'An e-mail has been sent with your receipt'
		}
		# Check to see if transaction was already in the database to avoid the user from
		# attempting to gain membership again without paying.
		if (query_db("SELECT * FROM transactions WHERE token=?", (transaction_id,), True) == None):
			# Change the user status to MEMBER to become an official member.
			update("users", ("status",), "id=?", ("MEMBER", session['id']))
			memberType = "ACM" if transaction.amount == 20 else "AECC"
			# Insert the newly processed transaction and store the memberType according
			# to the amount paid by the user. 20 for ACM, 5 for AECC

			insert("transactions", ("uid", "tdate", "token", "membertype"), (session['id'], transaction.created_at, transaction_id, memberType))
			html = render_template('receipt.html', transaction = transaction, membertype = memberType, user = user)
			subject = "Receipt"
			emailToken.send_email(user['email'], subject, html)
	# Something went wrong when processing the transaction.
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
	# Check if the amount received by HTML form is indeed $5 or $20.
	try:
		# If int conversion fails, the amount was altered by the user or something went wrong.
		amount = int(request.form['amount'])
		# 5 for standard AECC membership, 20 for AECC + ACM membership.
		if amount == 5 or amount == 20:
			result = braintree.Transaction.sale({
				'amount': request.form['amount'],
				'payment_method_nonce': request.form['payment_method_nonce'],
				'options': {
					"submit_for_settlement": True
				}
			})
			# Transaction was successfully processed.
			if result.is_success or result.transaction:
				return redirect(url_for('show_checkout',transaction_id=result.transaction.id))
			# Something went wrong with the transaction.
			else:
				for x in result.errors.deep_errors: flash('Error: %s: %s' % (x.code, x.message))
				return redirect(url_for('new_checkout'))
		# Wrong amount value entered for payment.
		else:
			flash('Error: Incorrect membership payment amount.', 'danger')
			return redirect(url_for('new_checkout'))
	# If int conversion fails, jump to this except catch block.
	except:
		flash('Error: Incorrect membership payment amount.', 'danger')
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
	maxEventsPerList = 3
	upcoming = query_db("SELECT * FROM events WHERE edate>=? ORDER BY edate ASC LIMIT ?", [str(datetime.now()), maxEventsPerList])
	past = query_db("SELECT * FROM events WHERE edate<? ORDER BY edate DESC LIMIT ?", [str(datetime.now()), maxEventsPerList])
	# Sort upcoming events so that the closest in date appear first rather than future ones.
	upcoming.sort(key=lambda x: x['edate'], reverse=True)
	return render_template('home.html', currentEvents=upcoming, pastEvents=past)

@app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

# Members
@app.route('/members')
def members():
	# Extracts active members from db
	results = query_db("SELECT id,studentFirstName,studentLastName,email,customPicture FROM users WHERE status = 'MEMBER'")
	return render_template('members.html', results=results)

# Members
@app.route('/about')
def about():
	directiveFolder = getDirectiveFolder().replace('static/', '')
	# Extracts admin info from db
	directivaMembers = query_db("SELECT studentID,studentFirstName,studentLastName,customPicture FROM users WHERE priviledge = 'ADMIN'")
	return render_template('about.html', directiva=directivaMembers, directiveFolder=directiveFolder)

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
			if query_db("SELECT id FROM users WHERE studentID = ?", [studentID]) == None:
				flash('Student Number already taken.', 'danger')
			elif query_db("SELECT id FROM users WHERE email = ? and priviledge != 'ADMIN'", [email]) == None:
				flash('Email address already taken.', 'danger')
			elif query_db("SELECT id FROM users WHERE phoneNumber = ?", [phoneNumber]) == None:
				flash('Phone Number already taken.', 'danger')
			# Valid major check
			elif query_db("SELECT * FROM majors WHERE mname = ?", [str(request.form['majors'])], True) == None:
				flash('Invalid Major entered.', 'danger')
			else:
				# Generate a random salt
				random_salt = urandom(64)
				# Encode the salt to store its hex value into the database
				salt = random_salt.encode('hex')
				# Generate the hash using the password and salt
				password = scrypt.hash(form.password.data.encode('utf-8'), random_salt).encode('hex')
				# Store the values into variables to avoid repetition
				firstName = form.studentFirstName.data
				lastName = form.studentLastName.data
				
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
	error = ""
	if request.method == 'POST':
		# Default error when visitor attempts login with invalid credentials.
		error = "Incorrect username or password."
		logging_with_email = False
		validCredentials = False

		# Get Form Fields
		username = str(request.form['username']).lower()
		# User is login with their email address
		if username.endswith("@upr.edu"):
			if len(username) >= 10 and len(username) <= 35:
				logging_with_email = True
				validCredentials = True
		# Otherwise user wants to login with their Student Number or with an Administrative account.
		elif username.isdigit() or username in directivaMemberList:
			validCredentials = True
		# If username is in the correct, now attempt to find the user in the database and compare passwords.
		if validCredentials:
			password_candidate = request.form['password'].encode('utf-8')
			# Get user by username. Admins can only login with their board member title. Regular users can login with email or with student ID number.
			result = query_db("SELECT id,studentFirstName,email,password,salt,customPicture,confirmation,priviledge FROM users WHERE email = ? and priviledge != 'ADMIN'", (username,), True) if logging_with_email else query_db("SELECT id,studentFirstName,email,password,salt,customPicture,confirmation,priviledge FROM users WHERE studentID = ?", (username,), True)
			if result != None:
				# Decode retrieved salt and hashed password
				uni_salt = result['salt'].decode('hex')
				password = result['password'].decode('hex')
				# Compare passwords by combining the (entered password + salt) with the hashed password.
				if scrypt.hash(password_candidate, uni_salt) == password:
					# Passed with matching password
					error = ""
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

	return render_template('login.html', error=error)

# ==== Forgot Password ====
# https://navaspot.wordpress.com/2014/06/25/how-to-implement-forgot-password-feature-in-flask/

def get_token(id, expiration=1800):
		s = Serializer(app.config['SECRET_KEY'], expiration)
		return s.dumps({'user': id}).decode('utf-8')

def verify_token(token):
	# Loads the json data from the token passed and extracts the id of the user
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
		# Extracts corresponding user id
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
			new_password = scrypt.hash(password_submit_form.password.data.encode('utf-8'), random_salt).encode('hex')
			
			# Resets password where account is not admin
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
	# Extracts if user confirmed
	user = query_db("SELECT confirmation FROM users WHERE email=? and priviledge != 'ADMIN'", (email,), True)
	if user != None:
		if user['confirmation']:
			flash('Your account is already confirmed', 'success')
		else:
			# Updates user with confirmation and confirmation date
			update("users", ("confirmation","confirmed_on"), "email=?", (1, datetime.now(), email))

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
	# Extracts users who are not members nor admins
	anythingButMembers = query_db("SELECT id,studentFirstName,studentLastName,email,customPicture,status FROM users WHERE status != 'MEMBER' and priviledge != 'ADMIN'")
	return render_template('admin.html', result=anythingButMembers)

@app.route('/activate/<string:id>/<string:memberType>')
@is_logged_in
@is_admin
def activateMembership(id, memberType):
	# Extracts user membership status
	result = query_db("SELECT status,studentFirstName,studentLastName FROM users WHERE id = ? and priviledge !='ADMIN'", [id], True)
	if result:
		if result['status'] == "MEMBER":
			flash(result['studentFirstName'] + " " + result['studentLastName'] + " is already an active member.", 'warning')
			return redirect(url_for('adminPanel'))
	else:
		flash('User does not exist.', 'danger')
		return redirect(url_for('adminPanel'))
	# Sets user status to MEMBER
	update("users", ("status",), "id=?", ('MEMBER', id))
	# Inserts activation info into manual activations table. Membertype temporarily according to the clicked activate button.
	insert("manual_activations", ("uid", "aid", "tdate", "membertype"), (id, session["id"], datetime.now(), memberType))
	flash(result['studentFirstName'] + " " + result['studentLastName'] + " is now a member!", "success")
	return redirect(url_for('adminPanel'))

@app.route('/suspend/<string:id>')
@is_logged_in
@is_admin
def suspendMembership(id, studentFirstName="", studentLastName=""):
	# Extracts user membership status
	result = query_db("SELECT status,studentFirstName,studentLastName FROM users WHERE id = ?", [id], True)
	if result:
		if result['status'] == "SUSPENDED":
			flash(result['studentFirstName'] + " " + result['studentLastName'] + " is already suspended.", 'warning')
			return redirect(url_for('members'))
	else:
		flash('User does not exist.', 'danger')
		return redirect(url_for('members'))
	# Sets membership status to suspended
	update("users", ("status",), "id=?", ('SUSPENDED', id))
	flash(result['studentFirstName'] + " " + result['studentLastName'] + " has been suspended!", "danger")
	return redirect(url_for('members'))

# === EVENTS === #

@app.route('/create-event',  methods=['GET', 'POST'])
@is_logged_in
@is_admin
def create_event():
	form = EventForm(request.form)
	if request.method == 'POST' and form.validate_on_submit():
		eventID = insert("events", ("etitle", "edate", "elocation", "edescription"), (form.title.data, form.date.data, form.location.data, form.body.data))
		return redirect(url_for('event', eid=eventID))
	return render_template("create_event.html", form=form)

@app.route('/edit-event/<string:eid>',  methods=['GET', 'POST'])
@is_logged_in
@is_admin
def edit_event(eid):
	eventInfo = query_db("SELECT * FROM events WHERE eid=?", [eid], True)
	if eventInfo == None:
		return render_template("404.html")
	form = EventForm(title=eventInfo['etitle'], date=eventInfo['edate'], location=eventInfo['elocation'], body=eventInfo['edescription'])
	if request.method == 'POST' and form.validate_on_submit():
		update("events", ("etitle", "edate", "elocation", "edescription"), "eid=?", (form.title.data, form.date.data, form.location.data, form.body.data, eventInfo['eid']))
		return redirect(url_for('event', eid=eid))
	return render_template("edit_event.html", form=form)

@app.route('/delete-event/<string:eid>')
@is_logged_in
@is_admin
def delete_event(eid):
	delete("events", "eid=?", [eid])
	return redirect(url_for('events'))

@app.route('/event/<string:eid>')
def event(eid):
	event = query_db("SELECT edate, etitle, elocation, edescription FROM events WHERE eid=?", [eid], True)
	return render_template("event.html", event=event)

@app.route('/events')
def events():
	eventList = query_db("SELECT * FROM events ORDER BY edate")
	upcoming = [event for event in eventList if event['edate'].encode('utf-8') > str(datetime.now())]
	# Sort by most recent to least recent
	upcoming.sort(key=lambda x: x['edate'], reverse=True)
	upcomingIDs = [eid['eid'] for eid in upcoming]
	past = [event for event in eventList if event['eid'] not in upcomingIDs]
	past.reverse()
	return render_template("events.html", upcoming=upcoming, past=past)

# === PROFILE === #

def getDirectiveFolder():
	currentdate = datetime.now()
	directiveyear = currentdate.year if currentdate.month >= 8 else currentdate.year - 1
	currentDirectiveFolder = "static/images/directiva{}".format(directiveyear)
	if not path.exists(currentDirectiveFolder):
		makedirs(currentDirectiveFolder)
	return currentDirectiveFolder

#Edit profile
@app.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@is_logged_in
@is_allowed_edit
def edit_profile(id):
	# Gets student's name and email by id
	result = query_db("SELECT studentFirstName,studentLastName,email,biography FROM users WHERE id = ?", [id], True)
	if result == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# If admin, get different form with admin email
	if session['id'] == id and session['admin']:
		courses = []
		userCourseIDs = []
		form = AdminForm(studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'], adminEmail=result['email'])
	# Else the user has the same id or the admin is in another users info
	else:
		# TODO: Pre-fill values of courses already taken by the user
		userCourseIDs = query_db("SELECT cid FROM courses_taken where uid=?", [id])
		userCourseIDs = [ucID['cid'] for ucID in userCourseIDs]
		courses = query_db("SELECT * FROM courses")
		form = ProfileForm(studentFirstName=result['studentFirstName'], studentLastName=result['studentLastName'], biography=result['biography'])
	if request.method == 'POST' and form.validate_on_submit():
		# Extracts password and salt to validate
		pass_salt = query_db("SELECT password,salt FROM users WHERE id = ?", [id], True)
		# Admin can bypass password verification or user must match their password
		if session['id'] != id or scrypt.hash(form.password.data.encode('utf-8'), pass_salt['salt'].decode('hex')) == pass_salt['password'].decode('hex'):
			studentFirstName = form.studentFirstName.data
			studentLastName = form.studentLastName.data
			f = request.files['uploadFile']
			filename = secure_filename(f.filename)
			if session['id'] == id and session['admin']:
				fieldsToUpdate = ["studentFirstName", "studentLastName"]
				fieldValues = [studentFirstName, studentLastName]
			else:
				fieldsToUpdate = ["studentFirstName", "studentLastName", "biography"]
				fieldValues = [studentFirstName, studentLastName, form.biography.data]
			if filename != "":
				filename = secure_filename(f.filename)
				filename = str(id)+"."+str(filename.split('.')[-1])
				for img in glob.glob(app.config['UPLOAD_FOLDER'] + "/" + str(id)+".*"):
					if path.exists(img):
						remove(img)
				f.save(path.join(app.config['UPLOAD_FOLDER'], filename))
				# To store images of directives
				if session['id'] == id and session['admin']:
					currentDirectiveFolder = getDirectiveFolder()
					for img in glob.glob(currentDirectiveFolder + "/" + str(id)+".*"):
						if path.exists(img):
							remove(img)
					if path.exists(currentDirectiveFolder):
						copy2(path.join(app.config['UPLOAD_FOLDER']+"/{}".format(filename)), currentDirectiveFolder)

				fieldsToUpdate.append("customPicture")
				fieldValues.append(filename)
			if str(form.new_password.data) != "":
				random_salt = urandom(64)
				new_salt = random_salt.encode('hex')
				new_password = scrypt.hash(form.new_password.data.encode('utf-8'), random_salt).encode('hex')
				fieldsToUpdate.extend(["password", "salt"])
				fieldValues.extend([new_password, new_salt])

			fieldValues.append(id)
			# Update the database to include the new set parameters by the user
			update("users", fieldsToUpdate, "id=?", fieldValues)
			if (session['id'] != id and session['admin']) or (session['id'] == id and not session['admin']):
				# Grab all the checkboxes that were checked
				course_ids = request.form.getlist("course_ids")
				# Secure against code injecting checkboxes
				allCourseIDs = [u'{}'.format(course['cid']) for course in courses]
				# Intersect all ids in database to find the matching with the checkboxes
				course_ids = list(set(course_ids).intersection(set(allCourseIDs)))
				# Insert and delete courses taken by the user
				for cid in userCourseIDs:
					# User removed a class
					if cid not in course_ids:
						delete("courses_taken", "uid=? and cid=?", (id, cid))
				for cid in course_ids:
					# User added a class
					if cid not in userCourseIDs:
						insert("courses_taken", ("uid", "cid"), (id, cid))

			# If admin is editing the profile, only change the session variables for the user
			if session['id'] == id:
				if session['admin'] and str(form.adminEmail.data) != "":
					# Sets admin email to lowercase
					update("users", ("email",), "id=?", (str(form.adminEmail.data).lower(), id))
				session['username'] = studentFirstName
				if filename != "":
					session['customPicture'] = filename
			flash('User profile modified', 'success')
		else:
			flash('Password is incorrect', 'danger')
		return redirect(url_for('edit_profile', id=id))
	return render_template('edit_profile.html', form=form, courses=courses, userCourseIDs=userCourseIDs, id=id)

@app.route('/user/<string:id>')
def user_profile(id):
	# Get public user information by id
	user = query_db("SELECT id,studentFirstName,studentLastName,email,biography,customPicture FROM users WHERE id = ?", (id,), True)
	# TODO: Query the courses taken by that user
	if user == None:
		flash('User does not exist in our database', 'danger')
		return render_template('404.html')
	# Check if the profile page belongs to the admin
	isAdminAccount = query_db("SELECT email FROM users WHERE id=? and priviledge='ADMIN'", (id,), True)
	# If it does, redirect to the page of the user with the same email account
	if isAdminAccount:
		# Checks if email exists in users table from non admin user
		hasSameEmail = query_db("SELECT id FROM users WHERE email=? and priviledge!='ADMIN'", (isAdminAccount['email'],), True)
		if hasSameEmail:
			return redirect(url_for('user_profile', id=hasSameEmail['id']))
		else:
			flash('User does not exist in our database', 'danger')
			return render_template('404.html')
	# Check if the user is logged in and is their own profile page
	if 'logged_in' in session and session['id'] == int(id):
		# Checks if user is not admin nor a member nor suspended
		if not session['admin'] and query_db("SELECT status FROM users WHERE id=? and status!='MEMBER' and status!='SUSPENDED'", (id,), True):
			flash(Markup('You have not paid your membership. <a href="'+url_for('new_checkout')+'">Click here to pay online.</a>'), 'warning')
		# Check if the user's account is confirmed
		if not session['confirmation']:
			flash(Markup('Please confirm your account! Didn\'t get the email? <a href="'+url_for('resend_confirmation')+'">Resend</a>'), 'warning')
		return render_template('user_profile.html', user=user)
	return render_template('user_profile.html', user=user)


if __name__ == '__main__':
	app.run(debug=True)
