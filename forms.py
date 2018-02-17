from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, TextAreaField, BooleanField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from db import query_db

# Register Form Class
class RegisterForm(FlaskForm):
	# Accept only digits for Student Number
	studentID = StringField('Student Number', validators=[validators.Regexp("\d{9}",message = "Enter a valid Student Number"),validators.DataRequired(), validators.Length(min=9, max=9)])

	email = EmailField('Email', validators=[validators.DataRequired(), validators.Length(min=10, max=35), validators.Email()])
	studentFirstName = StringField('First Name', validators=[validators.Regexp("\D",message = "Enter a valid First Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	studentLastName = StringField('Last Name', validators=[validators.Regexp("\D",message = "Enter a valid Last Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	phoneNumber = StringField('Phone Number', validators=[validators.Regexp("\d{10}",message = "Enter Phone Number"),validators.DataRequired(), validators.Length(min=10, max=10)])
	# Password must have at least 8 characters long, at least 1 number, at least 1 uppercase
	password = PasswordField('Password', validators=[
		validators.DataRequired(), validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match'),
		validators.Regexp("\d.*[A-Z]|[A-Z].*\d", message="Password must contain at least 1 uppercase letter and number.")])
	confirm = PasswordField('Confirm Password')
	# Check to redirect to transaction payment
	payNow = BooleanField("Pay Membership now?")

# Admin Form for when an admin edits a profile
class AdminForm(FlaskForm):
	uploadFile = FileField("Upload Avatar", validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Images only!')])
	studentFirstName = StringField('First Name', validators=[validators.Length(min=1,max=25)])
	studentLastName = StringField('Last Name', validators=[validators.Length(min=1,max=25)])
	# Add regular expression to check if endswith('@upr.edu')
	adminEmail = EmailField('Administrative Email', validators=[validators.Length(min=10, max=35), validators.Email()])
	password = PasswordField('Current Password', [
		validators.DataRequired(message='Enter your password to make any changes.')
	])
	new_password = PasswordField('New Password', validators=[
		validators.EqualTo('confirm', message='Passwords do not match'), 
		validators.Regexp("(^$)|(\d.*[A-Z]|[A-Z].*\d)", message="Password must contain at least 1 uppercase letter and number.")
	])
	confirm = PasswordField('Confirm New Password')

# Regular Edit Profile Form for when a non-admin user edits their profile
class ProfileForm(FlaskForm):
	uploadFile = FileField("Upload Avatar", validators=[FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Images only!')])
	studentFirstName = StringField('First Name', validators=[validators.Length(min=1,max=25)])
	studentLastName = StringField('Last Name', validators=[validators.Length(min=1,max=25)])
	password = PasswordField('Current Password (Enter to make any changes)', [
		validators.DataRequired(message='Enter your password to make any changes.')
	])
	new_password = PasswordField('New Password', [
		validators.EqualTo('confirm', message='Passwords do not match'),
		validators.Regexp("(^$)|(\d.*[A-Z]|[A-Z].*\d)", message="Password must contain at least 1 uppercase letter and number.")
	])
	confirm = PasswordField('Confirm New Password')
	Facebook = StringField('Facebook', validators=[validators.Length(max=50)])
	LinkedIn = StringField('LinkedIn', validators=[validators.Length(max=50)])
	GitHub = StringField('GitHub', validators=[validators.Length(max=75)])

	biography = TextAreaField('Biography', validators=[validators.Length(max=5000)])


class EventForm(FlaskForm):
	# Accept only digits for Student Number
	title = StringField('Event Title', validators=[validators.DataRequired(), validators.Length(max=100)])
	date = StringField('Date (YYYY-MM-DD)', validators=[validators.DataRequired(), validators.Length(max=100), validators.Regexp("([2]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))",message = "Wrong date format.")])	
	location = StringField('Location', validators=[validators.DataRequired(), validators.Length(max=100)])	
	body = TextAreaField('Description', validators=[validators.DataRequired(), validators.Length(max=5000)])

# ==== Forgot Password ====
# https://navaspot.wordpress.com/2014/06/25/how-to-implement-forgot-password-feature-in-flask/
class ExistingUser(object):
	def __init__(self, message="Email does not exist."):
		self.message = message
	def __call__(self, form, field):
		# Checks if email is in database
		if not query_db("SELECT id FROM users WHERE email=? and priviledge != 'ADMIN'", (field.data,), True):
			raise validators.ValidationError(self.message)

class ResetPassword(FlaskForm):
	email = EmailField('Email', validators=[validators.Required(),
		  validators.Email(),
		  ExistingUser(message='Email address is not available.')
		 ])

class ResetPasswordSubmit(FlaskForm):
	# TODO Add password custom validator
	# password = PasswordField('Password', validators=custom_validators['edit_password'])
	password = PasswordField('Password', validators=[validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match'), validators.Regexp("[A-Z]", message="Password must contain at least 1 uppercase letter."),
		validators.Regexp("\d.*[A-Z]|[A-Z].*\d", message="Password must contain at least 1 uppercase letter and number.")
		])
	confirm = PasswordField('Confirm Password')