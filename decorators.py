from db import query_db
from flask import redirect, url_for, session
from functools import wraps

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

# Check if the user is an administrator
def is_admin(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'ADMIN' in query_db("SELECT priviledge FROM users WHERE id=?", [session['id']], True):
			return f(*args, **kwargs)
		else:
			flash('Unauthorized: You do not have sufficient priviledges.', 'danger')
			return redirect(url_for('login'))
	return wrap

# Check if the user is editing their own profile or an admin is editing the user's profile
def is_allowed_edit(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'ADMIN' in query_db("SELECT priviledge FROM users WHERE id=?", [session['id']], True) or str(kwargs['id']) == str(session['id']):
			return f(*args, **kwargs)
		else:
			flash('Unauthorized: Attempting to modify information from other user.', 'danger')
			return redirect(url_for('edit_profile', id=session['id']))
	return wrap

def anonymous_user_required(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' not in session:
			return f(*args, **kwargs)
		else:
			flash('Logout to use this feature.', 'danger')
			return redirect(url_for('index'))
	return wrap