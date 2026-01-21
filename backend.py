from flask import Flask, render_template, request,session
import mysql.connector
import random
from datetime import datetime
import pandas as pd
import os
from datetime import date
from tensorflow.keras.models import load_model
import joblib
import numpy as np
import re

app = Flask(__name__)

app.secret_key = '12345678'
conn_data = {
     "host":'localhost',
    "user":'root',
    "password":'',
    "database":'mail_phishing'
}
def clean_text(text):
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

def classify_text(text):
    model = load_model("model.h5")
    tfidf = joblib.load("tfidf_vectorizer.pkl")
    text = clean_text(text)
    vector = tfidf.transform([text]).toarray()
    prediction = np.argmax(model.predict(vector), axis=1)[0]
    return prediction


@app.route('/register', methods=["GET"])
def register():
    return render_template('register.html')

@app.route('/contact', methods=["GET"])
def cntact():
    return render_template('contact.html')
@app.route('/about', methods=["GET"])
def about():
    return render_template('about.html')


@app.route('/dashboard', methods=["GET"])
def dashboard():
    if session["user_id"] != -1:
        return render_template('login.html')
    else:
        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT emp_id,fullname,detect_rate FROM evaluation,users WHERE emp_id = users.id
                """)
        results = cursor.fetchall()

        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT count(emp_id),fullname FROM result,users WHERE emp_id = users.id group by emp_id
                """)
        total = cursor.fetchall()

        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT count(emp_id),fullname FROM result,users WHERE emp_id = users.id and evaluated like 'This is right%' group by emp_id
                """)
        right = cursor.fetchall()
        print(total,right)
        return render_template('statistics.html',message = {"table":results,"total":total,"right":right})



@app.route('/logout', methods=["GET"])
def logout():
    session.clear()
    return render_template('login.html')

@app.route('/home', methods=["GET"])
def home():
    return render_template('home.html')

@app.route('/evaluate', methods=["GET"])
def evaluate():
    df = pd.read_csv("phishing_mail_dataset.csv")
    df = df.sample(frac=1)
    sampled_rows = df[['text', 'label']].sample(n=5)
    mails = sampled_rows['text'].tolist()
    labels = sampled_rows['label'].tolist()
    session[str(session["user_id"])+"_labels"] = labels
    session[str(session["user_id"])+"_mails"] = mails
    return render_template('evaluate.html',message={"mails":mails})


@app.route('/add_account', methods=["POST"])
def add_account():
       
        conn = mysql.connector.connect(
                    host=conn_data["host"],
                    user=conn_data["user"],
                    password=conn_data["password"],
                    database=conn_data["database"]
            )
        name = request.form.get('fullname')
        email = request.form.get('email')
        password = request.form.get('password')
        cursor = conn.cursor()
        cursor.execute("""
                INSERT INTO users (fullname, email, password)
                VALUES (%s, %s, %s)
            """, (name, email, password))
        conn.commit()
        conn.close()
        return render_template('login.html')

@app.route('/check_evaluation', methods=["GET"])
def check_evaluation():
    safe = request.args.get("safe")
    phish = request.args.get("phish")
    safe = safe.split(",")
    phish = phish.split(",")
    print("nnnn,",safe)
    labels=[]
    mails = session[str(session["user_id"])+"_mails"] 
    for m in mails:
        labels.append(int(classify_text(m)))
    print("######",labels)
    if safe[0] != "":
        for i in range(len(safe)):
            safe[i] = int(safe[i])
    if phish[0] != "":
        for i in range(len(phish)):
            phish[i] = int(phish[i])
    ev_list=[0] * len(labels)
    if safe[0] != "":
        for e in safe:
            ev_list[e]=1
    if phish[0] != "":
        for e in phish:
            ev_list[e]=0
         
    res = []
    r_count = 0
    for i in range(len(labels)):
        if labels[i] == ev_list[i]:
            res.append("This is right, you are doing well in phish email detection")
            r_count+=1
        else:
            res.append("Unfortunately, this is wrong, you are failure to detect phishing email, please increase your experience")

    conn = mysql.connector.connect(
                    host=conn_data["host"],
                    user=conn_data["user"],
                    password=conn_data["password"],
                    database=conn_data["database"]
            )
    emp_id = session["user_id"]
    cursor = conn.cursor()
    for i in range(len(mails)):

        
        cursor.execute("""
                    INSERT INTO result (emp_id, mails,evaluated)
                    VALUES (%s, %s,%s)
                """, (emp_id, mails[i],res[i]))
        conn.commit()
    conn.close()
    conn = mysql.connector.connect(
                    host=conn_data["host"],
                    user=conn_data["user"],
                    password=conn_data["password"],
                    database=conn_data["database"]
            )
    rate = r_count/len(res)
    cursor = conn.cursor()
    cursor.execute("""
                INSERT INTO evaluation (emp_id, detect_rate)
                VALUES (%s, %s)
            """, (emp_id, rate))
    conn.commit()
    conn.close()
    return render_template('results.html',message={"mails":mails,"res":res,"ev":True})

@app.route('/login', methods=["GET"])
def login():
    return render_template('login.html')


@app.route('/login_act', methods=["POST"])
def login_act():
    email = request.form.get('email')
    password = request.form.get('password')
    if email == "admin@gmail.com" and password == "admin":
        session["user_id"] = -1
        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT emp_id,fullname,detect_rate FROM evaluation,users WHERE emp_id = users.id
                """)
        results = cursor.fetchall()
        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT count(emp_id),fullname FROM result,users WHERE emp_id = users.id group by emp_id
                """)
        total = cursor.fetchall()

        conn = mysql.connector.connect(
                        host=conn_data["host"],
                        user=conn_data["user"],
                        password=conn_data["password"],
                        database=conn_data["database"]
                )
        cursor = conn.cursor()
        cursor.execute("""
                    SELECT count(emp_id),fullname FROM result,users WHERE emp_id = users.id and evaluated like 'This is right%' group by emp_id
                """)
        right = cursor.fetchall()
        return render_template('statistics.html',message = {"table":results,"total":total,"right":right})
    conn = mysql.connector.connect(
                    host=conn_data["host"],
                    user=conn_data["user"],
                    password=conn_data["password"],
                    database=conn_data["database"]
            )
    cursor = conn.cursor()
    cursor.execute("""
                SELECT id FROM users WHERE email = %s and password=%s
            """, (email,password))
    result = cursor.fetchall()
    if result:
         result = result[0]
    cursor.close()
    if result:
        session['user_id'] = result[0]
        return render_template('Home.html',message="done")
    return render_template('login.html',message="error")
    


app.run()