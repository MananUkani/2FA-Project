from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import base64
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')  # Use environment variable for secret key

def get_db_connection():
    conn = sqlite3.connect(os.getenv('DATABASE_PATH', 'mfa.db'))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                mfa_secret TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    qr_code = None

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form['username']
        password = request.form['password']

        if action == 'register':
            conn = get_db_connection()
            cur = conn.cursor()
            mfa_secret = pyotp.random_base32()
            try:
                cur.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                            (username, password, mfa_secret))
                conn.commit()
                
                # Generate QR code
                otp_uri = pyotp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name='YourApp')
                qr = qrcode.make(otp_uri)
                buffered = BytesIO()
                qr.save(buffered, 'PNG')
                qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
                qr_code = qr_base64
                
                flash('Registration successful! Scan the QR code to set up MFA.')
            except sqlite3.IntegrityError:
                flash('Username already exists. Please log in instead.')
            finally:
                conn.close()

        elif action == 'login':
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            conn.close()
            
            if user and user['password'] == password:
                # Store MFA secret in session to use it for verification
                session['username'] = username
                session['mfa_secret'] = user['mfa_secret']
                return redirect(url_for('mfa_verification'))
            else:
                flash('Invalid username or password')

    return render_template('index.html', qr_code=qr_code)

@app.route('/mfa_verification', methods=['GET', 'POST'])
def mfa_verification():
    if 'username' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        mfa_token = request.form['mfa_token']
        totp = pyotp.TOTP(session['mfa_secret'])
        if totp.verify(mfa_token):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA token')

    return render_template('mfa_verification.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('mfa_secret', None)
    return redirect(url_for('index'))

@app.route('/delete', methods=['POST'])
def delete():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    session.pop('username', None)
    session.pop('mfa_secret', None)
    flash('Account deleted successfully.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
