
# MySQL Configuration
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError, EqualTo
import bcrypt
import re
from datetime import datetime, timedelta
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import random

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'ELJLH7KB42eqEqEabF7idfNOI5h3EXBh72vT4CKx82g='  
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
# app.config['JWT_COOKIE_CSRF_PROTECT'] = False  # Set to True and handle CSRF in forms for better security
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)


# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Your SMTP server, e.g., Gmail
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'thapamanil37@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'kbaj ndpp ines huxf'  # Replace with your email password or app-specific password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

mail = Mail(app)


jwt = JWTManager(app)

DB_USERNAME = 'sparsh' # Change this to your username
DB_PASSWORD = 'sparsh' # Change this to your password
DB_HOST = 'localhost' # Change this to your MySQL host
DB_NAME = 'acs' # Change this to your database name
# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

migrate = Migrate(app, db)

app.secret_key = 'your_secret_key_here'

# Serializer for email verification and password reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def model_to_dict(model):
    """Converts a SQLAlchemy model instance into a dictionary."""
    return {column.name: getattr(model, column.name) for column in model.__table__.columns}


class User(db.Model):
    __tablename__ = 'users'  # Specify the table name if it's already existing
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_time = db.Column(db.DateTime, nullable=True)
    otp = db.Column(db.String(6))  # Store the OTP code
    otp_expiration = db.Column(db.DateTime)  # Store the OTP expiration time
    email_confirmed = db.Column(db.Boolean, default=False)

def send_otp_email(user_email, otp):
    msg = Message(
        subject="OTP for Account Verification",
        sender=app.config['MAIL_USERNAME'],
        recipients=[user_email],
        body=f'Your OTP code is {otp}. It is valid for 5 minutes.'
    )
    mail.send(msg)

def send_reset_email(to_email, reset_url):
    msg = Message(
        subject="Password Reset Request",
        sender=app.config['MAIL_USERNAME'],
        recipients=[to_email],
        body=f'Click on the link to reset your password: {reset_url}'
    )
    mail.send(msg)


def generate_otp(user):
    otp = str(random.randint(100000, 999999))  # 6-digit OTP
    user['otp'] = otp
    user['otp_expiration'] = datetime.now() + timedelta(minutes=5)  # OTP valid for 5 minutes
    db.session.commit()
    send_otp_email(user['email'], otp)  # Call function to send OTP
    return otp 

def generate_reg_otp():
    return str(random.randint(100000, 999999))  # 6-digit OTP


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

class EditProfileForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email")
    submit = SubmitField("Update Profile")

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

    
    # Validate if name is already taken
    def validate_name(self, field):
        user = User.query.filter_by(name=field.data).first()
        if user:
            raise ValidationError('Name already taken')

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# Context processor to inject csrf_token
@app.context_processor
def inject_csrf():
    csrf_token = request.cookies.get('csrf_access_token')
    return dict(csrf_token=csrf_token)

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
        userExist = User.query.filter_by(email=email).first()
        email_confirmed = True
        if userExist:
            email_confirmed = userExist.email_confirmed 


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

            if lockout_time and datetime.now() < lockout_time:
                flash("Too many failed attempts. Please try again later.")
                return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                user.failed_attempts = 0
                user.lockout_time = None
                db.session.commit()

                # Create JWT token
                access_token = create_access_token(identity=user.id)

                # Set the JWT in a cookie
                response = redirect(url_for('dashboard'))
                response.set_cookie('access_token', access_token, httponly=True)

                flash('Login Successful!', 'success')
                return response
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

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    user_id = session['user_id']
    if not user_id:
        print("user_id not ", user_id)

        flash('Session expired or invalid access. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp = request.form['otp']
        print("otp is ---->" , otp)
        # Fetch the user and verify OTP
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT otp, otp_expiration FROM users WHERE id = %s", [user_id])
        user = cursor.fetchone()
        cursor.close()
        print("user response ---> " , user)
        if user:
            stored_otp, otp_expiration = user
            if stored_otp == otp:
                # Check if the OTP has expired
                if otp_expiration >= datetime.now():
                    # Log the user in now that OTP is verified
                    login_user(load_user(session['user_id']))
                    session['otp_verified'] = True
                    flash('OTP verified. You are now logged in!', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('The OTP has expired. Please log in again.', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
        else:
            flash('Invalid session. Please log in again.', 'danger')
            return redirect(url_for('login'))

    return render_template('verify_otp.html')



@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if user:
        return render_template('dashboard.html', user=user)
    else:
        flash("User not found.")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.delete_cookie('access_token')
    flash("You have been logged out")
    return response

@app.route('/edit_profile', methods=['GET', 'POST'])
@jwt_required()
def edit_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user: 
        flash("User not found.")
        return redirect(url_for('login'))


    form = EditProfileForm()


    if form.validate_on_submit():
        new_name = form.name.data

        if User.query.filter(User.name == new_name, User.id != user.id).first():
            flash('Name already taken')
            return render_template('edit_profile.html', form=form)

        user.name = new_name

        db.session.commit()

        flash('Your profile has been updated!')
        return redirect(url_for('dashboard'))

    # Pre-populate the form fields with current user info
    form.name.data = user.name
    form.email.data = user.email

    return render_template('edit_profile.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)

