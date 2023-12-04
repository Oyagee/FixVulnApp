from flask import Flask, request, render_template, redirect
import sqlite3
from markupsafe import escape
import os
import subprocess


app = Flask(__name__, template_folder='templates')

# XSS
@app.route("/")
def index():
    name = request.args.get("name", "")
    return f"<h1>Hello, {name}!</h1>"

#SQLI and BRUTE FORCE

conn = sqlite3.connect('database.db', check_same_thread=False)
cursor = conn.cursor()

@app.route("/sqli/")
def sqli():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()

    if result:
        return "<h1>Login successful.</h1>", 201
    else:
        return "<h1>Deny</h1>", 400





############## IDOR


users = [
    {"id": 1, "name": "Роман", "email": "@mail.ru"},
    {"id": 2, "name": "Алексей", "email": "@gmail.com"},
]

@app.route('/idor/')
def idor():
    return render_template('idor.html', users=users)


@app.route('/user/<int:user_id>')
def user_profile(user_id):
    for user in users:
        if user['id'] == user_id:
            return render_template('profile.html', user=user)
    return redirect('/')

#### Path Traversal

@app.route('/pathtraversal/')
def pathtraversal():
    return render_template('pathtraversal.html')


@app.route('/read_file', methods=['POST'])
def read_file():
    filename = request.form.get('filename')
    filepath = os.path.join('uploads', filename)

    try:
        with open(filepath, 'r') as file:
            content = file.read()
            return content
    except Exception as e:
        return str(e)



### Brute Force

@app.route('/login')
def log():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    if username == 'admin' and password == 'password':
        return "<h1>Login successful.</h1>"
    else:
        return "<h1>Deny.</h1>"


### OS command injection

@app.route('/osci')
def osci():
    return render_template('osci.html')

@app.route('/execute', methods=['POST'])
def execute():
    command = request.form.get('command')
    return subprocess.check_output(command, shell=True)

if __name__ == "__main__":
    app.run(debug=True)

