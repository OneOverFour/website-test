from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tracker.db'
db = SQLAlchemy(app)

# Define User and Torrent models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    approved = db.Column(db.Boolean, default=False)
    torrents = db.relationship('Torrent', backref='user', lazy=True)

class Torrent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_key = db.Column(db.String(64), nullable=False)
    size_mb = db.Column(db.Float, nullable=False)
    # Add more fields as needed

# Define routes
@app.route('/')
def index():
    torrents = Torrent.query.all()
    return render_template('index.html', torrents=torrents)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('User registration submitted. Please wait for admin approval.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.approved:
                session['user_id'] = user.id
                flash('Login successful.')
                return redirect(url_for('index'))
            else:
                flash('User not approved yet. Please wait for admin approval.')
        else:
            flash('Login failed. Check your username and password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('index'))

# Implement routes for torrent uploading, admin approval, torrent listing, etc.

# Run the app
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
