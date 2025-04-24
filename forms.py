from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class UploadFileForm(FlaskForm):
    file = FileField('Select File', validators=[FileRequired()])
    encryption_password = PasswordField('Encryption Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('encryption_password')])
    submit = SubmitField('Encrypt & Upload')

class DecryptFileForm(FlaskForm):
    encryption_password = PasswordField('Encryption Password', validators=[DataRequired()])
    submit = SubmitField('Decrypt')

class ShareFileForm(FlaskForm):
    username = StringField('Username to share with', validators=[DataRequired()])
    submit = SubmitField('Share File')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is None:
            raise ValidationError('User not found.')
