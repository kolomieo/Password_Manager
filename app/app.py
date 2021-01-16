from flask import Flask, render_template, flash, redirect, request, session, url_for
from flask_sqlalchemy import SQLAlchemy

import forms

from forms import LoginForm, RegisterForm, AddForm, MasterForm
import os

from Crypto.Cipher import AES


import argon2

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from OpenSSL import SSL

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from flask_wtf.csrf import CSRFProtect





app = Flask(__name__)
CSRFProtect(app)

app.config['SECRET_KEY'] = os.urandom(128) 

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SESSION_COOKIE_SECURE'] = True


session_id = None

ph = argon2.PasswordHasher()

limiter = Limiter(  
    app,
    key_func=get_remote_address
)

db = SQLAlchemy(app)

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(15), unique=False)

    email = db.Column(db.String(50), unique=True)

    password = db.Column(db.String(256), unique=False)

    master_password = db.Column(db.String(256), unique=False)

    pwmanagers = db.relationship('PwManager', backref = 'owner')

class PwManager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(256))
    password = db.Column(db.String(256))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@app.route('/',methods = ['GET','POST'])
def home():
    form_add = AddForm(request.form)
    form_master = MasterForm(request.form)
    global master_password
    email = session.get("email")

    result = User.query.filter_by(email = email).first()

    if session.get("master") == False:
        if request.method == 'POST' and form_master.validate():
            try:
                ph.verify(result.master_password , form_master.master_password.data)
            except Exception:
                flash('Master Password Incorrect')
                return render_template('index.html', user_one= result, form_add = form_add,form_master=form_master)
            else:
                session['master'] = True 
                master_password = form_master.master_password.data
        
        else:
            return render_template('index.html', user_one= result, form_add = form_add,form_master=form_master)


    if session.get("master") == True:

        if request.method == 'POST' and form_add.validate():
            new_pass = form_add.password.data
        
            encrypted_password = encrypt(new_pass, master_password)
        
            new_pwmanager = PwManager(
                
                url = form_add.url.data, 
                
                password = encrypted_password, 
                
                owner_id = session.get("id")
            )
        
            db.session.add(new_pwmanager)
        
            db.session.commit()
        
            for pw in result.pwmanagers:
                pw.password = decrypt(pw.password, master_password)
        
            return render_template('index.html', user_one= result, form_add = form_add,form_master=form_master,master_password = master_password)

        
        else:
            for pw in result.pwmanagers:
                pw.password = decrypt(pw.password, master_password)
        
            return render_template('index.html', user_one= result, form_add = form_add,form_master=form_master,master_password = master_password)
    else:
        return render_template('index.html', user_one= result, form_add = form_add,form_master=form_master)


@app.route('/login/', methods = ['GET', 'POST'])

@limiter.limit("10 per minute", 
               error_message="You have tried to log in too many times. Please wait a moment and try again.")

def login():

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate:

        user = User.query.filter_by(email = form.email.data).first()

        if user:
                try:
                    ph.verify(user.password, form.password.data)
                except Exception:
                    flash('Password Incorrect')
                    return redirect(url_for('login'))
                else:

                    flash('You have successfully logged in.', "success")
                    
                    session['logged_in'] = True

                    session['email'] = user.email 

                    session['username'] = user.username

                    session['id'] = user.id

                    session['master'] = False

                    return redirect(url_for('home'))

        else:
            flash('Email Incorrect')

            return redirect(url_for('login'))


            

    return render_template('login.html', form = form)


@app.route('/register/', methods = ['GET', 'POST'])
def register():
    
    form = RegisterForm(request.form)
    
    if request.method == 'POST' and form.validate():
        if bool(User.query.filter_by(email=form.email.data).first()) == False:
            hashed_password = ph.hash(form.master_password.data)
            hashed_master_password = ph.hash(form.master_password.data)
        
            new_user = User(
                            
                username = form.username.data, 
                
                email = form.email.data, 
                
                password = hashed_password,

                master_password = hashed_master_password
            )
        
            db.session.add(new_user)
        
            db.session.commit()
        
            flash('You have successfully registered', 'success')

            return redirect(url_for('login'))
        else:
            flash ('This email or username is already registered')
            return render_template('register.html', form = form)
    
    else:
    
        return render_template('register.html', form = form)

@app.route('/logout/')
def logout():
    
    session['logged_in'] = False

    return redirect(url_for('home'))

def encrypt(url_password, master_password):
    ciphertext = b""
    salt = get_random_bytes(32) 
    key = scrypt(master_password, salt, key_len=32, N=2**17, r=8, p=1)
    ciphertext = ciphertext + salt
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext = ciphertext + cipher.nonce
    encrypted_data = cipher.encrypt(url_password.encode("utf8"))
    ciphertext = ciphertext + encrypted_data
    return ciphertext

def decrypt(ciphertext,master_password):
    ciphertext = ciphertext
    salt = ciphertext[0:32]
    key = scrypt(master_password, salt, key_len=32, N=2**17, r=8, p=1) 
    nonce = ciphertext[32:48]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data = ciphertext[48:]
    decrypted_data = cipher.decrypt(data) 
    return decrypted_data.decode("utf8")

    
@app.after_request
def remove_header(response):

    response.headers['server'] = 'hidden'

    return response


if __name__ == '__main__':
    
    db.create_all()
    app.run(host = "0.0.0.0",ssl_context=('cert.pem', 'key.pem'),debug=True)


