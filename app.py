from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import base64
import os
from logging_config import setup_logging  # Import the logging configuration

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Hardcoded secret key

setup_logging()  # Set up logging

def get_db_connection():
    try:
        conn = sqlite3.connect('mfa.db')  # Hardcoded database path
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        app.logger.error(f"Database connection error: {e}")
        return None

def init_db():
    try:
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
    except sqlite3.Error as e:
        app.logger.error(f"Database initialization error: {e}")

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
            if conn is None:
                flash('Database connection error. Please try again later.')
                return render_template('index.html', qr_code=qr_code)
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
            except sqlite3.Error as e:
                app.logger.error(f"Database error during registration: {e}")
                flash('An error occurred during registration. Please try again.')
            finally:
                conn.close()

        elif action == 'login':
            conn = get_db_connection()
            if conn is None:
                flash('Database connection error. Please try again later.')
                return render_template('index.html', qr_code=qr_code)
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
    if conn is None:
        flash('Database connection error. Please try again later.')
        return redirect(url_for('index'))
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        flash('Account deleted successfully.')
    except sqlite3.Error as e:
        app.logger.error(f"Database error during account deletion: {e}")
        flash('An error occurred while deleting the account. Please try again.')
    finally:
        conn.close()

    session.pop('username', None)
    session.pop('mfa_secret', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
