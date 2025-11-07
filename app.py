# app.py - Deliberately Insecure Flask CRUD Mini-App
# For software security labs (SQLi, XSS, bad crypto, etc.)
# DO NOT use this code in production!

from flask import Flask, request, session, redirect, url_for, render_template_string, send_from_directory, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecret'  # Hardcoded secret key (bad)
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --- DATABASE INIT ---
def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    # Users: plaintext pw, no unique constraint
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, is_admin INTEGER DEFAULT 0)''')
    # Notes: content (no input filtering)
    c.execute('''CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner_id INTEGER, content TEXT)''')
    conn.commit()
    conn.close()
init_db()

# --- AUTH (deliberately broken) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    # No password complexity, no username uniqueness, plaintext storage
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute(f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')")
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return '''
    <h2>Register</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Register">
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Vulnerable: No lockout, compares plaintext, hardcoded admin account
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute(f"SELECT id, is_admin FROM users WHERE username='{username}' AND password='{password}'")
        row = c.fetchone()
        if row:
            session['user_id'] = row[0]
            session['is_admin'] = bool(row[1])
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed')
    return '''
    <h2>Login</h2>
    <form method="post">
      Username: <input name="username"><br>
      Password: <input name="password" type="password"><br>
      <input type="submit" value="Login">
    </form>
    <a href="/register">Register</a>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Vulnerable: No session expiration, no CSRF, shows XSS in notes
    return f'''
    <h2>Dashboard</h2>
    <a href="/new_note">Add Note</a> | <a href="/notes">My Notes</a> | <a href="/upload">Upload</a> | <a href="/admin">Admin</a> | <a href="/logout">Logout</a>
    '''

# --- CRUD for Notes (SQLi, XSS, IDOR) ---
@app.route('/new_note', methods=['GET', 'POST'])
def new_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form['content']  # No input validation
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        # SQLi: unsanitised input
        c.execute(f"INSERT INTO notes (owner_id, content) VALUES ({session['user_id']}, '{content}')")
        conn.commit()
        conn.close()
        return redirect(url_for('notes'))
    return '''
    <h2>New Note</h2>
    <form method="post">
      Content: <input name="content"><br>
      <input type="submit" value="Save">
    </form>
    '''

@app.route('/notes')
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # IDOR: any user can view all notes with ?owner_id= param
    owner_id = request.args.get('owner_id', session['user_id'])
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    # SQLi: unsanitised owner_id
    c.execute(f"SELECT id, content FROM notes WHERE owner_id={owner_id}")
    notes = c.fetchall()
    conn.close()
    # XSS: rendering unescaped
    notes_html = "".join([f"<li>{render_template_string(n[1])}</li>" for n in notes])
    return f'''
    <h2>Notes</h2>
    <ul>{notes_html}</ul>
    <a href="/dashboard">Back</a>
    '''

# --- FILE UPLOAD (unsafe) ---
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files['file']
        # Insecure: No filename or type validation
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        return f'File {file.filename} uploaded! <a href="/dashboard">Back</a>'
    return '''
    <h2>Upload File</h2>
    <form method="post" enctype="multipart/form-data">
      File: <input type="file" name="file"><br>
      <input type="submit" value="Upload">
    </form>
    '''

@app.route('/uploads/<filename>')
def uploads(filename):
    # Insecure: possible directory traversal
    return send_from_directory(UPLOAD_FOLDER, filename)

# --- COMMAND INJECTION (dangerous!) ---
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = ''
    if request.method == 'POST':
        host = request.form['host']
        # Insecure: unsanitised input to os.system
        result = os.popen(f'ping -c 1 {host}').read()
    return f'''
    <h2>Ping Utility</h2>
    <form method="post">
      Host: <input name="host"><br>
      <input type="submit" value="Ping">
    </form>
    <pre>{result}</pre>
    <a href="/dashboard">Back</a>
    '''

# --- ADMIN (no proper authZ) ---
@app.route('/admin')
def admin():
    if not session.get('is_admin'):
        return 'Access denied', 403
    # Privilege escalation flaw: users can make themselves admin via /make_admin?user_id=
    return '''
    <h2>Admin Panel</h2>
    <a href="/make_admin?user_id=1">Promote user 1 to admin (INSECURE!)</a><br>
    <a href="/dashboard">Back</a>
    '''

@app.route('/make_admin')
def make_admin():
    # No auth check, no CSRF
    user_id = request.args.get('user_id')
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute(f"UPDATE users SET is_admin=1 WHERE id={user_id}")
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True)

