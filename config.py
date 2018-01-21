import os
#class BaseConfig(object):
"""Base configuration."""

# main config
SECRET_KEY = 'secret123'
SECURITY_PASSWORD_SALT = 'AECC_Salt'
DEBUG = True
BCRYPT_LOG_ROUNDS = 13
WTF_CSRF_ENABLED = True
DEBUG_TB_ENABLED = False
DEBUG_TB_INTERCEPT_REDIRECTS = False
UPLOAD_FOLDER = 'static/uploads'
MAX_CONTENT_LENGTH = 10 * 1024 * 1024 # 10MB

# mail settings
MAIL_SERVER = 'smtp.googlemail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USE_SSL = False

# gmail authentication
#MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
#MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']
MAIL_USERNAME = 'websiteaecc@gmail.com'
MAIL_PASSWORD = 'aeccwebsite2018'

# mail accounts
#MAIL_DEFAULT_SENDER = 'noreply@aecc.com'