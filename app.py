from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
import re  # For regex to validate strong passwords
from flask_mysqldb import MySQL
import sys
from datetime import datetime, timedelta

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'mydatabase'
app.secret_key = 'your_secret_key_here'

mysql = MySQL(app)


# Check MySQL Database Connection
def check_db_connection():
    try:
        with app.app_context():  # Set up application context
            # Attempt to create a cursor and execute a simple query
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT 1")  # Simple query to check connection
            cursor.close()
            print("Database connection successful.")
    except Exception as e:
        # If there is an error, print it and exit the app
        print(f"Error: Could not connect to the database. {e}")
        sys.exit(1)  # Terminate the app if the connection fails

# Call the function to check the connection before the app starts
check_db_connection()


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
    email = StringField("Email", validators=[DataRequired(), Email()])
    current_password = PasswordField("Current Password")
    new_password = PasswordField("New Password", validators=[validate_password_strength])
    confirm_password = PasswordField("Confirm New Password")
    submit = SubmitField("Update Profile")

# Register form with added name validation to prevent duplicates
class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), validate_password_strength])  # Added password validator
    submit = SubmitField("Register")

    # Validate if email is already taken
    def validate_email(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (field.data,))
        user = cursor.fetchone()
        cursor.close()
        if user:
            raise ValidationError('Email already taken')
    
    # Validate if name is already taken
    def validate_name(self, field):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE name=%s", (field.data,))
        user = cursor.fetchone()  # Fetch one user with the given name
        cursor.close()
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
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store data into the database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, hashed_password))
        mysql.connection.commit()
        cursor.close()

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

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user:
            failed_attempts = user[4]  # Assuming 'failed_attempts'
            lockout_time = user[5]  # Assuming 'lockout_time' 

            if lockout_time:
                current_time = datetime.now()
                if current_time < lockout_time:
                    flash("Too many failed attempts. Please try again after 1 minute.")
                    cursor.close()
                    return redirect(url_for('login'))

            if bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
                cursor.execute("UPDATE users SET failed_attempts=0, lockout_time=NULL WHERE email=%s", (email,))
                mysql.connection.commit()

                session['user_id'] = user[0]
                cursor.close()

                # Success flash message here
                flash('Login Successful!', 'success')

                return redirect(url_for('dashboard'))
            else:
                new_attempts = failed_attempts + 1
                if new_attempts >= 3:
                    lockout_time = datetime.now() + timedelta(minutes=1)
                    cursor.execute("UPDATE users SET failed_attempts=%s, lockout_time=%s WHERE email=%s",
                                   (new_attempts, lockout_time, email))
                    flash("Too many failed attempts. Please try again after 1 minute.")
                else:
                    cursor.execute("UPDATE users SET failed_attempts=%s WHERE email=%s",
                                   (new_attempts, email))
                    flash("Login failed. Please check your email and password.")
                
                mysql.connection.commit()

        else:
            flash("Email does not exist.")

        cursor.close()
        return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

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
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()

    if form.validate_on_submit():
        
        new_name = form.name.data
        new_email = form.email.data

        cursor.execute("UPDATE users SET name=%s, email=%s WHERE id=%s", (new_name, new_email, session['user_id']))

        # Check if the user is updating the password
        if form.new_password.data:
            # Hash the new password
            new_hashed_password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE users SET password=%s WHERE id=%s", (new_hashed_password, session['user_id']))
            flash('Your password has been updated!')

        mysql.connection.commit()
        cursor.close()

        flash('Your profile has been updated!')
        return redirect(url_for('dashboard'))

    # Pre-populate the form fields with current user info
    form.name.data = user[1]  # Assuming 'name' 
    form.email.data = user[2]  # Assuming 'email' n

    return render_template('edit_profile.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)