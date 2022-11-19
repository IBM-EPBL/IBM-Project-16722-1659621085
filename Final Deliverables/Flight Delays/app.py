from errno import ENAMETOOLONG
from turtle import st
from flask import Flask, render_template, request, redirect, url_for, session
import numpy as np 
import pandas as pd
import pickle
import os
import requests
from markupsafe import escape
from flask_mail import Mail, Message
from random import randint
import ibm_db
conn = ibm_db.connect("DATABASE=bludb;HOSTNAME=764264db-9824-4b7c-82df-40d1b13897c2.bs2io90l08kqb1od8lcg.databases.appdomain.cloud;PORT=32536;SECURITY=SSL;SSLServerCertificate=DigiCertGlobalRootCA.crt;UID=kzy64909;PWD=ex8AdzTg57abUK25",'','')

GOOGLE_CLIENT_ID = "340644155083-hm83b3k5d7mbb0ps5u33ck7qkbder4uf.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
REDIRECT_URI = '/gentry/auth'

import json
# NOTE: you must manually set API_KEY below using information retrieved from your IBM Cloud account.
API_KEY = "mYBrvKJylOO4wCWoS_TesMMELMxEBSW9rQ1NzP0Wn-se"
token_response = requests.post('https://iam.cloud.ibm.com/identity/token', data={"apikey":
API_KEY, "grant_type": 'urn:ibm:params:oauth:grant-type:apikey'})
mltoken = token_response.json()["access_token"]

header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}
model = pickle.load(open('flight.pkl','rb'))
app = Flask(__name__)

app.secret_key = 'flightdelayflyhigh2022'
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


@app.route('/prediction',methods=["POST","GET"])
def prediction():
  if request.method == 'POST':
    global name
    global month
    global day_of_month
    global day_of_week  
    global origin
    global ans

    name = request.form['name']
    month = request.form['month']
    day_of_month = request.form['day_of_month']
    day_of_week = request.form['day_of_week']
    origin = request.form['origin']
    ans = 'No delay'
    print(origin)
    if(origin  == 'MSP'):
      origin1, origin2, origin3, origin4, origin5 = 0, 0, 0, 0, 1
    if(origin  == 'DTW'):
      origin1, origin2, origin3, origin4, origin5 = 1, 0, 0, 0, 0
    if(origin  == 'JFK'):
      origin1, origin2, origin3, origin4, origin5 = 0, 0, 1, 0, 0
    if(origin  == 'SEA'):
      origin1, origin2, origin3, origin4, origin5 = 0, 1, 0, 0, 0
    if(origin  == 'ALT'):
      origin1, origin2, origin3, origin4, origin5 = 0, 0, 0, 1, 0

    destination = request.form['destination']
    if(destination == 'MSP'):
      destination1, destination2, destination3, destination4, destination5 = 0, 0, 0, 0, 1
    if(destination == 'DTW'):
      destination1, destination2, destination3, destination4, destination5 = 1, 0, 0, 0, 0
    if(destination == 'JFK'):
      destination1, destination2, destination3, destination4, destination5 = 0, 0, 1, 0, 0
    if(destination == 'SEA'):
      destination1, destination2, destination3, destination4, destination5 = 0, 1, 0, 0, 0
    if(destination == 'ALT'):
      destination1, destination2, destination3, destination4, destination5 = 0, 0, 0, 1, 0

    dept = request.form['dept']
    arrtime = request.form['arrtime']
    actdept = request.form['actdept']
    
    dept15 = int(dept) - int(actdept)
    total = [[name, month, day_of_month, day_of_week,dept15, arrtime, origin1,origin2,origin3,origin4,origin5,destination1,destination2,destination3,destination4,destination5]]
    print(total)
    # payload_scoring = {"input_data": [{"field": ['f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8','f9', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15'], "values":total}]}
    # response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/ml/v4/deployments/739a6f52-043e-49ec-b5ee-d9b2d5a4e6b6/predictions?version=2022-11-19', json=payload_scoring,
    # headers={'Authorization': 'Bearer ' + mltoken})
    # y_pred = response_scoring.json()
    y_pred = model.predict(total)
    print(y_pred)
    # pred_result = y_pred['predictions'][0]['values'][0][0]
    # print(pred_result)
    # if(pred_result == 0):
    print(y_pred)
    if(y_pred == 0):
      ans = 'Yippeeee! The flight will be on time.'
    else:
      ans = 'Sorry! Your flight will be delayed.'
    print(ans)
    return render_template('result.html', prediction = ans)
  return render_template('Prediction.html')



@app.route('/gentry')
def gentry():
    return redirect(f"https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/userinfo.profile&access_type=offline&include_granted_scopes=true&response_type=code&redirect_uri=http://127.0.0.1:5000/gentry/auth&client_id={GOOGLE_CLIENT_ID}")

@app.route('/gentry/auth')
def gentry_auth():
    r = requests.post("https://oauth2.googleapis.com/token", 
    data={
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "code": request.args.get("code"),
        "grant_type": "authorization_code",
        "redirect_uri": "http://127.0.0.1:5000/gentry/auth"
    })

    r = requests.get(f'https://www.googleapis.com/oauth2/v2/userinfo?access_token={r.json()["access_token"]}').json()
    print("====================================================")
    print(r) 
    print("====================================================")

  
    return redirect(url_for('home'))


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


