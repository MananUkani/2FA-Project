from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import base64
import os
from logging_config import setup_logging  # Import the logging configuration

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = '11223344556677889900abcde12345'  # Hardcoded secret key

setup_logging()  # Set up logging

def get_db_connection():
    try:
        conn = sqlite3.connect('mfa.db')  # Hardcoded database path
        conn.row_factory = sqlite3.Row
        app.logger.info("Database connection established")
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
            app.logger.info("Database initialized")
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
        app.logger.info(f"Form submitted with action: {action}, username: {username}")

        if action == 'register':
            conn = get_db_connection()
            if conn is None:
                app.logger.error("Database connection error")
                flash('Database connection error. Please try again later.')
                return render_template('index.html', qr_code=qr_code)
            cur = conn.cursor()
            mfa_secret = pyotp.random_base32()
            try:
                cur.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                            (username, password, mfa_secret))
                conn.commit()
                app.logger.info(f"User {username} registered successfully")
                
                # Generate QR code
                app.logger.info("Generating QR code")
                otp_uri = pyotp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name='YourApp')
                qr = qrcode.make(otp_uri)
                buffered = BytesIO()
                qr.save(buffered, format='PNG')  # Specify format explicitly
                qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
                qr_code = qr_base64
                app.logger.info("QR code generated successfully")
                
                flash('Registration successful! Scan the QR code to set up MFA.')
            except sqlite3.IntegrityError:
                app.logger.warning(f"Username {username} already exists")
                flash('Username already exists. Please log in instead.')
            except sqlite3.Error as e:
                app.logger.error(f"Database error during registration: {e}")
                flash('An error occurred during registration. Please try again.')
            finally:
                conn.close()

        elif action == 'login':
            conn = get_db_connection()
            if conn is None:
                app.logger.error("Database connection error")
                flash('Database connection error. Please try again later.')
                return render_template('index.html', qr_code=qr_code)
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            conn.close()
            
            if user and user['password'] == password:
                app.logger.info(f"User {username} logged in successfully")
                # Store MFA secret in session to use it for verification
                session['username'] = username
                session['mfa_secret'] = user['mfa_secret']
                return redirect(url_for('mfa_verification'))
            else:
                app.logger.warning(f"Invalid login attempt for username: {username}")
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
            app.logger.info(f"MFA verification successful for user: {session['username']}")
            return redirect(url_for('dashboard'))
        else:
            app.logger.warning(f"Invalid MFA token for user: {session['username']}")
            flash('Invalid MFA token')

    return render_template('mfa_verification.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    app.logger.info(f"User {session.get('username')} logged out")
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
        app.logger.error("Database connection error")
        flash('Database connection error. Please try again later.')
        return redirect(url_for('index'))
    cur = conn.cursor()
    try:
        cur.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        app.logger.info(f"User {username} deleted successfully")
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
