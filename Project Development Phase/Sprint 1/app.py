'''from errno import ENAMETOOLONG
from turtle import st
from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import escape
from flask_mail import Mail, Message
from random import randint

import ibm_db
conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=764264db-9824-4b7c-82df-40d1b13897c2.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=32536;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=kzy64909;PWD=ex8AdzTg57abUK25",'','')

app = Flask(__name__)
mail = Mail(app)

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = '2k19cse104@kiot.ac.in'
app.config['MAIL_PASSWORD'] = 'kiotcse@19'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

otp = randint(000000, 999999)
Name = ""
Email = ""
Password = ""
ConfirmPassword =""


@app.route('/')
def home():
  return render_template('home_page.html')

@app.route('/signup')
def signup():
  return render_template('Sign_Up.html')
 

 
@app.route('/register',methods = ['POST', 'GET'])
def register():
  if request.method == 'POST': 
    Name = request.form['Name']
    Email = request.form['Email']
    Password = request.form['Password']
    ConfirmPassword = request.form['ConfirmPassword']
    sql = "SELECT * FROM Profiles WHERE name =?"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt,1,Name)
    ibm_db.execute(stmt)
    account = ibm_db.fetch_assoc(stmt)

    if account:
      return render_template('Sign_Up.html', msg="You are already a member, please login using your details")
    else:
      global otp
      otp = randint(000000, 999999)
      email = Email
      msg = Message(subject='OTP', sender='2k19cse104@kiot.ac.in',
                    recipients=[email])
      msg.body = "You have succesfully registered!\nThe OTP for verification is\n\t" + \
            str(otp)
      mail.send(msg)
      return render_template('otp_verification.html', resendmsg="OTP has been resent")
    
  email = request.form['Email']
  msg = Message(subject='OTP', sender='2k19cse104@kiot.ac.in',
                recipients=[email])
  msg.body = "You have succesfully registered !\nThe OTP for verification is\n\t" + \
      str(otp)
  mail.send(msg)
  return render_template('otp_verification.html')
  
@app.route('/validate', methods=['POST'])
def validate():
    global otp
    user_otp = request.form['otp']
    if otp == int(user_otp):
  
       insert_sql = "INSERT INTO Profiles VALUES (?,?,?,?)"
       prep_stmt = ibm_db.prepare(conn, insert_sql)
       ibm_db.bind_param(prep_stmt, 1, Name)
       ibm_db.bind_param(prep_stmt, 2, Email)
       ibm_db.bind_param(prep_stmt, 3, Password)
       ibm_db.bind_param(prep_stmt, 4, ConfirmPassword)
       ibm_db.execute(prep_stmt)
       return render_template('Sign_Up.html')
    else:
        return render_template('otp_verification.html', msg="OTP is invalid. Please enter a valid OTP")


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        Email = request.form.get('Email')
        Password = request.form.get('Password')

        sql = "SELECT * FROM user WHERE Email =?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, Email)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if account:
            if (Password == str(account['PASS']).strip()):
                return render_template('home_page.html')
            else:
                return render_template('Sign_Up.html', msg="Password is invalid")
        else:
            return render_template('Sign_Up.html', msg="Email is invalid")
    else:
        return render_template('Sign_Up.html')


if(__name__ ==  '__main__'):
  app.run(host = '0.0.0.0', port =5000)


'''
from errno import ENAMETOOLONG
from turtle import st
from flask import Flask, render_template, request, redirect, url_for, session
from markupsafe import escape
from flask_mail import Mail, Message
from random import randint

import ibm_db
conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=764264db-9824-4b7c-82df-40d1b13897c2.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=32536;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=kzy64909;PWD=ex8AdzTg57abUK25",'','')

app = Flask(__name__)

app.config["MAIL_SERVER"] = 'smtp.gmail.com'
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = '2k19cse104@kiot.ac.in'
app.config['MAIL_PASSWORD'] = 'kiotcse@19'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

@app.route('/')
def home():
  return render_template('home_page.html')

@app.route('/signup')
def signup():
  return render_template('Sign_Up.html')
 
@app.route('/recoverymail')
def recoverymail():
  return render_template('recoverymail.html')

@app.route('/sendpassword', methods = ['POST'])
def sendpassword():
  if request.method == 'POST':
    email = request.form.get('email')
    sql = "SELECT * FROM Profiles WHERE Email =?"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt,1,email)
    ibm_db.execute(stmt)
    account = ibm_db.fetch_assoc(stmt)
    print("--------------------------------")
    print(account)
    if not account:
      return render_template('recoverymail.html', msg="You are not signed up")
    else:
      password = account['PASSWORD']
      msg = Message(subject='OTP', sender='2k19cse104@kiot.ac.in',recipients=[email])
      msg.body = "Your Password is: " + password
      mail.send(msg)
      return render_template('Sign_Up.html')
 
@app.route('/register',methods = ['POST', 'GET'])
def register():

  if request.method == 'POST':
    global Name
    global Email
    global Password
    global ConfirmPassword
    
    Name = request.form['Name']
    Email = request.form['Email']
    Password = request.form['Password']
    ConfirmPassword = request.form['ConfirmPassword']
    print(Name)
    sql = "SELECT * FROM Profiles WHERE name =?"
    stmt = ibm_db.prepare(conn, sql)
    ibm_db.bind_param(stmt,1,Name)
    ibm_db.execute(stmt)
    account = ibm_db.fetch_assoc(stmt)

    if account:
      return render_template('Sign_Up.html', msg="You are already a member, please login using your details")
    else:
      global otp
      otp = randint(000000, 999999)
      email = Email
      msg = Message(subject='OTP', sender='2k19cse104@kiot.ac.in',
                    recipients=[email])
      msg.body = "You have succesfully registered!\nThe OTP for verification is\n\t" + \
            str(otp)
      mail.send(msg)
      return render_template('otp_verification.html', resendmsg="OTP has been resent")
    
  email = request.form['Email']
  msg = Message(subject='OTP', sender='2k19cse104@kiot.ac.in',
                recipients=[email])
  msg.body = "You have succesfully registered !\nThe OTP for verification is\n\t" + \
      str(otp)
  mail.send(msg)
  return render_template('otp_verification.html')
  
  
@app.route('/validate', methods=['POST'])
def validate():
    global otp
    user_otp = request.form['otp']
    if otp == int(user_otp):
  
       insert_sql = "INSERT INTO Profiles VALUES (?,?,?,?)"
       prep_stmt = ibm_db.prepare(conn, insert_sql)
       ibm_db.bind_param(prep_stmt, 1, Name)
       ibm_db.bind_param(prep_stmt, 2, Email)
       ibm_db.bind_param(prep_stmt, 3, Password)
       ibm_db.bind_param(prep_stmt, 4, ConfirmPassword)
       ibm_db.execute(prep_stmt)
       return render_template('Sign_Up.html')
    else:
        return render_template('otp_verification.html', msg="OTP is invalid. Please enter a valid OTP")
    
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        Email = request.form.get('Email')
        Password = request.form.get('Password')

        sql = "SELECT * FROM user WHERE Email =?"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, Email)
        ibm_db.execute(stmt)
        account = ibm_db.fetch_assoc(stmt)

        if account:
            if (Password == str(account['PASS']).strip()):
                return render_template('home_page.html')
            else:
                return render_template('Sign_Up.html', msg="Password is invalid")
        else:
            return render_template('Sign_Up.html', msg="Email is invalid")
    else:
        return render_template('Sign_Up.html')

if(__name__ ==  '__main__'):
  app.run(host = '0.0.0.0', port =5000)


