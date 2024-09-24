
# MySQL Configuration

from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
import bcrypt
import re
import sys
from datetime import datetime, timedelta

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

app = Flask(__name__)

DB_USERNAME = 'dipesh' # Change this to your username
DB_PASSWORD = 'dipesh' # Change this to your password
DB_HOST = 'localhost' # Change this to your MySQL host
DB_NAME = 'acs' # Change this to your database name

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.secret_key = 'your_secret_key_here'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Custom validator for strong password
def validate_password_strength(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')
    if not re.search(r"[A-Z]", password):
        raise ValidationError('Password must contain at least one uppercase letter')
    if not re.search(r"[a-z]", password):
        raise ValidationError('Password must contain at least one lowercase letter')
    if not re.search(r"\d", password):
        raise ValidationError('Password must contain at least one digit')
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError('Password must contain at least one special character')

# User model
class User(db.Model):
    __tablename__ = 'users'  # Specify the table name if it's already existing
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)

class EditProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    current_password = PasswordField("Current Password")
    new_password = PasswordField("New Password", validators=[validate_password_strength, EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField("Confirm New Password")
    submit = SubmitField("Update Profile")

    # Validate if email is already taken
    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user and user.id != session.get('user_id'):
            raise ValidationError('Email already taken')

    # Validate if name is already taken
    def validate_name(self, field):
        user = User.query.filter_by(name=field.data).first()
        if user and user.id != session.get('user_id'):
            raise ValidationError('Name already taken')

# Register form with added name validation to prevent duplicates
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), validate_password_strength])
    confirm_password = PasswordField("Confirm Password")
    submit = SubmitField("Register")

    # Validate if email is already taken
    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email already taken')
    
    # Validate if name is already taken
    def validate_name(self, field):
        user = User.query.filter_by(name=field.data).first()
        if user:
            raise ValidationError('Name already taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Create a new user
        new_user = User(name=name, email=email, password=hashed_password)

        # Store data into the database
        db.session.add(new_user)
        db.session.commit()

        # Add success flash message here
        flash('Registration Successful! Please log in.', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user:
            failed_attempts = user.failed_attempts
            lockout_time = user.lockout_time

            if lockout_time:
                current_time = datetime.now()
                if current_time < lockout_time:
                    flash("Too many failed attempts. Please try again after 1 minute.")
                    return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                user.failed_attempts = 0
                user.lockout_time = None
                db.session.commit()

                session['user_id'] = user.id

                flash('Login Successful!', 'success')

                return redirect(url_for('dashboard'))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 3:
                    user.lockout_time = datetime.now() + timedelta(minutes=1)
                    flash("Too many failed attempts. Please try again after 1 minute.")
                else:
                    flash("Login failed. Please check your email and password.")

                db.session.commit()
        else:
            flash("Email does not exist.")

        return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        user = User.query.get(user_id)

        if user:
            return render_template('dashboard.html', user=user)

    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out")
    return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    form = EditProfileForm()

    # Fetch the current user info from the database
    user = User.query.get(session['user_id'])

    if form.validate_on_submit():
        new_name = form.name.data
        new_email = form.email.data

        # Check if the new email or name is already taken by another user
        if User.query.filter(User.email == new_email, User.id != user.id).first():
            flash('Email already taken')
            return render_template('edit_profile.html', form=form)

        if User.query.filter(User.name == new_name, User.id != user.id).first():
            flash('Name already taken')
            return render_template('edit_profile.html', form=form)

        user.name = new_name
        user.email = new_email

        # Check if the user is updating the password
        if form.new_password.data:
            # Verify current password
            if not bcrypt.checkpw(form.current_password.data.encode('utf-8'), user.password.encode('utf-8')):
                flash('Current password is incorrect.')
                return render_template('edit_profile.html', form=form)

            # Hash the new password
            new_hashed_password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            user.password = new_hashed_password
            flash('Your password has been updated!')

        db.session.commit()

        flash('Your profile has been updated!')
        return redirect(url_for('dashboard'))

    # Pre-populate the form fields with current user info
    form.name.data = user.name
    form.email.data = user.email

    return render_template('edit_profile.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)

