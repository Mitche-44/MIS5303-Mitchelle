from flask import Flask, request, session, redirect, url_for, send_from_directory, flash
import sqlite3
import os
import bcrypt
from markupsafe import escape
import subprocess
import shlex
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return 'Access denied', 403
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

def init_db():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, is_admin INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notes 
                 (id INTEGER PRIMARY KEY, owner_id INTEGER, content TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if len(username) < 3 or len(password) < 8:
            flash('Username must be at least 3 chars and password 8 chars')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                     (username, hashed_password))
            conn.commit()
            flash('Registration successful')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
        finally:
            conn.close()
    
    return '''
    <h2>Register</h2>
    <form method="post">
      Username: <input name="username" required minlength="3"><br>
      Password: <input name="password" type="password" required minlength="8"><br>
      <input type="submit" value="Register">
    </form>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute("SELECT id, password, is_admin FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        
        if row and bcrypt.checkpw(password.encode('utf-8'), row[1]):
            session['user_id'] = row[0]
            session['is_admin'] = bool(row[2])
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    
    return '''
    <h2>Login</h2>
    <form method="post">
      Username: <input name="username" required><br>
      Password: <input name="password" type="password" required><br>
      <input type="submit" value="Login">
    </form>
    <a href="/register">Register</a>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return '''
    <h2>Dashboard</h2>
    <a href="/new_note">Add Note</a> | 
    <a href="/notes">My Notes</a> | 
    <a href="/upload">Upload</a> | 
    <a href="/ping">Ping</a> | 
    <a href="/admin">Admin</a> | 
    <a href="/logout">Logout</a>
    '''

@app.route('/new_note', methods=['GET', 'POST'])
@login_required
def new_note():
    if request.method == 'POST':
        content = escape(request.form['content'])
        conn = sqlite3.connect('app.db')
        c = conn.cursor()
        c.execute("INSERT INTO notes (owner_id, content) VALUES (?, ?)", 
                 (session['user_id'], content))
        conn.commit()
        conn.close()
        flash('Note added successfully')
        return redirect(url_for('notes'))
    
    return '''
    <h2>New Note</h2>
    <form method="post">
      Content: <textarea name="content" required></textarea><br>
      <input type="submit" value="Save">
    </form>
    <a href="/dashboard">Back</a>
    '''

@app.route('/notes')
@login_required
def notes():
    conn = sqlite3.connect('app.db')
    c = conn.cursor()
    c.execute("SELECT id, content FROM notes WHERE owner_id=?", (session['user_id'],))
    notes = c.fetchall()
    conn.close()
    
    notes_html = "".join([f"<li>{n[1]}</li>" for n in notes])
    return f'''
    <h2>My Notes</h2>
    <ul>{notes_html}</ul>
    <a href="/dashboard">Back</a>
    '''

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            flash('File uploaded successfully')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid file type. Allowed: ' + ', '.join(ALLOWED_EXTENSIONS))
    
    return '''
    <h2>Upload File</h2>
    <form method="post" enctype="multipart/form-data">
      File: <input type="file" name="file" required><br>
      <input type="submit" value="Upload">
    </form>
    <a href="/dashboard">Back</a>
    '''

@app.route('/uploads/<filename>')
@login_required
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/ping', methods=['GET', 'POST'])
@login_required
def ping():
    result = ''
    if request.method == 'POST':
        host = request.form['host']
        if not host.replace('.', '').replace('-', '').isalnum():
            result = "Invalid hostname"
        else:
            safe_host = shlex.quote(host)
            try:
                process = subprocess.run(['ping', '-c', '1', safe_host], 
                                      capture_output=True, text=True, timeout=5)
                result = process.stdout
                if process.returncode != 0:
                    result += f"\nPing failed with return code {process.returncode}"
            except subprocess.TimeoutExpired:
                result = "Command timed out"
    
    return f'''
    <h2>Ping Utility</h2>
    <form method="post">
      Host: <input name="host" required pattern="[a-zA-Z0-9.-]+"><br>
      <input type="submit" value="Ping">
    </form>
    <pre>{escape(result)}</pre>
    <a href="/dashboard">Back</a>
    '''

@app.route('/admin')
@admin_required
def admin():
    return '''
    <h2>Admin Panel</h2>
    <p>Authorized admin access only</p>
    <a href="/dashboard">Back</a>
    '''

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)