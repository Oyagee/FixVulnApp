from flask import Flask, request, render_template, redirect, make_response
import sqlite3
import time
from markupsafe import escape
import os
import subprocess
from werkzeug.utils import secure_filename


app = Flask(__name__, template_folder='templates')

# XSS
@app.route("/")
def index():
    name = request.args.get("name", "")
    name = escape(name)
    return f"<h1>Hello, {name}!</h1>"

#SQLI and BRUTE FORCE

conn = sqlite3.connect('database.db', check_same_thread=False)
cursor = conn.cursor()

login_attempts = {}
MAX_ATTEMPTS = 5
TIME_INTERVAL = 60
@app.route("/sqli/")
def sqli():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    if username in login_attempts:
        attempts, last_attempt_time = login_attempts[username]

        elapsed_time = time.time() - last_attempt_time

        if elapsed_time < TIME_INTERVAL and attempts >= MAX_ATTEMPTS:
            return "<h1>Too many login attempts.</h1>", 429

    query = f"SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    result = cursor.fetchone()

    if result:
        if username in login_attempts:
            del login_attempts[username]
        return "<h1>Login successful.</h1>", 201
    else:
        if username in login_attempts:
            attempts, last_attempt_time = login_attempts[username]
            login_attempts[username] = (attempts + 1, time.time())
        else:
            login_attempts[username] = (1, time.time())
        return f"<h1>Deny.</h1>", 400

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

    if not os.path.isabs(filename):

        filename = secure_filename(filename)
        filepath = os.path.join('uploads', filename)

        if os.path.realpath(filepath).startswith(os.path.realpath('uploads')):
            try:
                with open(filepath, 'r') as file:
                    content = file.read()
                    return content
            except Exception as e:
                return str(e)

    return 'Некорректный путь к файлу'

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

