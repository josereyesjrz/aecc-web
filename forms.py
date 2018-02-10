from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, TextAreaField, BooleanField, PasswordField, validators
from wtforms.fields.html5 import EmailField
from db import query_db


# Register Form Class
class RegisterForm(FlaskForm):
	# Accept only digits for Student Number
	studentID = StringField('Student Number', [validators.Regexp("\d{9}",message = "Enter a valid Student Number"),validators.DataRequired(), validators.Length(min=9, max=9)])

	email = EmailField('Email', [validators.DataRequired(), validators.Length(min=10, max=35), validators.Email()])
	studentFirstName = StringField('First Name', [validators.Regexp("\D",message = "Enter a valid First Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	studentLastName = StringField('Last Name', [validators.Regexp("\D",message = "Enter a valid Last Name"),validators.DataRequired(), validators.Length(min=1,max=25)])	
	phoneNumber = StringField('Phone Number', [validators.Regexp("\d{10}",message = "Enter Phone Number"),validators.DataRequired(), validators.Length(min=10, max=10)])
	# TODO Add validators: At least 1 number, at least 1 uppercase
	password = PasswordField('Password', [
		validators.DataRequired(), validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('Confirm Password')
	# Check to redirect to transaction payment
	payNow = BooleanField("Pay Membership now?")

# Admin Form for when an admin edits a profile
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
	confirm = PasswordField('Confirm New Password')

# Regular Edit Profile Form for when a non-admin user edits their profile
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
	confirm = PasswordField('Confirm New Password')
	biography = TextAreaField('Biography', [validators.Length(max=5000)])

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
	password = PasswordField('Password', [validators.Length(min=8, max=30, message='Password must be at least 8 characters long and 30 max.'),
		validators.EqualTo('confirm', message='Passwords do not match')])
	confirm = PasswordField('Confirm Password')