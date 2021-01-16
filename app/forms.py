from wtforms import Form, BooleanField, StringField, PasswordField, validators, TextAreaField, IntegerField

from wtforms.validators import DataRequired

import re

def my_password_check(form, field):
    charRegex = re.compile(r'(\w{8,})') 
    lowerRegex = re.compile(r'[a-z]+') 
    upperRegex = re.compile(r'[A-Z]+')
    digitRegex = re.compile(r'[0-9]+') 

    if charRegex.findall(field.data) == []:  
        raise validators.ValidationError('Password must contain atleast 8 characters')
    elif lowerRegex.findall(field.data)==[]: 
        raise validators.ValidationError('Password must contain atleast one lowercase character')
    elif upperRegex.findall(field.data)==[]: 
        raise validators.ValidationError('Password must contain atleast one uppercase character')
    elif digitRegex.findall(field.data)==[]: 
        raise validators.ValidationError('Password must contain atleast one digit character')




class LoginForm(Form):

    email = StringField("Email", validators=[validators.Length(min=7, max=50), validators.DataRequired(message="Please Fill This Field")])

    password = PasswordField("Password", validators=[validators.DataRequired(message="Please Fill This Field")])


class RegisterForm(Form):
        
    username = StringField("Username", validators=[validators.Length(min=3, max=25), validators.DataRequired(message="Please Fill This Field") ])
    
    email = StringField("Email", validators=[validators.Email(message="Please enter a valid email address"),validators.Length(min=7, max=50)])
    
    password = PasswordField("Password", validators=[
    
        validators.DataRequired(message="Please Fill This Field"),
    
        validators.EqualTo(fieldname="confirm", message="Your Passwords Do Not Match"),
        
        my_password_check
    ])
    
    confirm = PasswordField("Confirm Password", validators=[validators.DataRequired(message="Please Fill This Field")])


    master_password = PasswordField("Master Password", validators=[
    
        validators.DataRequired(message="Please Fill This Field"),
    
        validators.EqualTo(fieldname="confirm_master", message="Your Passwords Do Not Match"),
        
        my_password_check

    ])
    
    confirm_master = PasswordField("Confirm Master Password", validators=[validators.DataRequired(message="Please Fill This Field")])

class AddForm(Form):

    url = StringField("url", validators=[validators.Length(min=3, max=50), validators.DataRequired(message="Please Fill This Field")])

    password = PasswordField("Password", validators=[validators.DataRequired(message="Please Fill This Field")])

class MasterForm(Form):
    master_password = PasswordField("Master_Password", validators=[validators.DataRequired(message="Please Fill This Field")])


