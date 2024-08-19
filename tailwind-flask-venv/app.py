from flask import Flask, render_template, request, redirect, flash, jsonify, session, url_for
from flask_login import LoginManager, UserMixin, login_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Email
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
import logging
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(16).hex()
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') or os.urandom(16).hex()
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_TYPE'] = 'filesystem'

jwt = JWTManager(app)
db = SQLAlchemy(app)
Session(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirmation = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Utility Functions
@app.before_request
def init_db():
    db.create_all()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        if User.query.filter_by(email=email).first():
            flash('User already registered')
        else:
            try:
                passhash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)
                new_user = User(email=email, password=passhash)
                db.session.add(new_user)
                db.session.commit()
                flash('Registered successfully')
                return redirect(url_for('home'))
            except Exception as e:
                logging.error(f"Error registering user: {e}")
                flash('Failed to register user')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password):
                access_token = create_access_token(identity=user.id)
                session['access_token'] = access_token
                login_user(user)
                return redirect(url_for('home'))  
            else:
                flash('Invalid email or password')
        except Exception as e:
            flash(f'An error occurred: {str(e)}')
    return render_template('login.html', form=form)

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return render_template('protected.html', user=current_user)

@app.route('/aboutus')
def aboutus():
    return render_template ('aboutus.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/product')
def product():
    return render_template('product.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=True)