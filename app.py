
# MySQL Configuration
from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
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
import sys

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'ELJLH7KB42eqEqEabF7idfNOI5h3EXBh72vT4CKx82g='  
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  #
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'thapamanil37@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'kbaj ndpp ines huxf'  # Replace with your email password or app-specific password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

DB_USERNAME = 'dipesh' # Change this to your username
DB_PASSWORD = 'dipesh' # Change this to your password
DB_HOST = 'localhost' # Change this to your MySQL host
DB_NAME = 'acs' # Change this to your database name
# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USERNAME}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


mail = Mail(app)
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

app.secret_key = 'your_secret_key_here'

# Serializer for email verification and password reset tokens
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def check_db_connection():
    try:
        # Attempt to create a connection to the database
        with db.engine.connect() as connection:
            # Execute a simple query to test the connection
            connection.execute(text("SELECT 1"))
            print("Database connection successful.")
    except Exception as e:
        # If there is an error, print it and exit the app
        print(f"Error: Could not connect to the database. {e}")
        sys.exit(1)  # Terminate the app if the connection fails

with app.app_context():
    check_db_connection()


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


def generate_otp():
    otp = str(random.randint(100000, 999999))  # 6-digit OTP
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

    def validate_email(self, field):
        user = User.query.filter_by(email=field.data).first()
        if user and user.email_confirmed:
            raise ValidationError('Email already registered and confirmed. Please log in or reset your password.')

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

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Check if a user with the email already exists
        existing_user = User.query.filter_by(email=email).first()


        if existing_user:
            if not existing_user.email_confirmed:
                # Update the existing user record with new data
                existing_user.name = name
                existing_user.password = hashed_password

                # Generate a new OTP
                otp = generate_reg_otp()
                existing_user.otp = otp
                existing_user.otp_expiration = datetime.now() + timedelta(minutes=5)
                db.session.commit()

                # Send OTP email
                send_otp_email(email, otp)

                # Store user ID in session to verify OTP later
                session['user_id'] = existing_user.id

                flash('An OTP has been sent to your email for verification.', 'success')
                return redirect(url_for('verify_registration_otp'))
            else:
                # Email exists and is confirmed
                flash('Email already registered and confirmed. Please log in or reset your password.', 'danger')
                return redirect(url_for('login'))
        else:
            # Create a new user record
            new_user = User(
                name=name,
                email=email,
                password=hashed_password,
                email_confirmed=False
            )

            # Generate OTP
            otp = generate_reg_otp()
            new_user.otp = otp
            new_user.otp_expiration = datetime.now() + timedelta(minutes=5)

            db.session.add(new_user)
            db.session.commit()

            # Send OTP email
            send_otp_email(email, otp)

            # Store user ID in session to verify OTP later
            session['user_id'] = new_user.id

            flash('Registration successful! Please verify your email with the OTP sent to you.', 'success')
            return redirect(url_for('verify_registration_otp'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user:
            if not user.email_confirmed:
                flash('Please verify your email before logging in.', 'warning')
                # Optionally, resend OTP
                session['user_id'] = user.id
                otp = generate_otp()
                user.otp = otp
                user.otp_expiration = datetime.now() + timedelta(minutes=5)
                db.session.commit()
                send_otp_email(user.email, otp)
                return redirect(url_for('verify_registration_otp'))

            failed_attempts = user.failed_attempts
            lockout_time = user.lockout_time

            if lockout_time and datetime.now() < lockout_time:
                flash("Too many failed attempts. Please try again later.")
                return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                user.failed_attempts = 0
                user.lockout_time = None
                db.session.commit()

                # Generate OTP for login
                otp = generate_otp()
                user.otp = otp
                user.otp_expiration = datetime.now() + timedelta(minutes=5)
                db.session.commit()
                send_otp_email(user.email, otp)

                # Store user ID in session to verify OTP later
                session['user_id'] = user.id

                flash('OTP sent to your email. Please verify to log in.', 'success')
                return redirect(url_for('verify_login_otp'))
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

@app.route('/verify-registration-otp', methods=['GET', 'POST'])
def verify_registration_otp():
    user_id = session['user_id']
    if not user_id:
        flash('Session expired or invalid access. Please register again.', 'danger')
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')

        user = User.query.get(user_id)

        if user and user.otp == otp_input:
            if datetime.now() <= user.otp_expiration:
                user.email_confirmed = True
                user.otp = None
                user.otp_expiration = None
                db.session.commit()
                session.pop('user_id', None)
                flash('Email verified successfully! You can now log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('OTP expired. Please register again.', 'danger')
                db.session.delete(user)
                db.session.commit()
                session.pop('user_id', None)
                return redirect(url_for('register'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_registration_otp.html')

@app.route('/verify-login-otp', methods=['GET', 'POST'])
def verify_login_otp():
    user_id = session['user_id']
    if not user_id:
        flash('Session expired or invalid access. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = request.form.get('otp')
        user = User.query.get(user_id)

        if user and user.otp == otp_input:
            if datetime.now() <= user.otp_expiration:
                # Create JWT token
                access_token = create_access_token(identity=user.id)

                # Clear OTP fields
                user.otp = None
                user.otp_expiration = None
                db.session.commit()

                # Set the JWT in a cookie
                response = redirect(url_for('dashboard'))
                response.set_cookie('access_token', access_token, httponly=True)

                session.pop('user_id', None)

                flash('Login Successful!', 'success')
                return response
            else:
                flash('OTP expired. Please log in again.', 'danger')
                session.pop('user_id', None)
                return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_login_otp.html')

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

