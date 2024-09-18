from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
from PIL import Image
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '156abeefdbbaccc7896532486'

# Directory for QR codes
if not os.path.exists('static'):
    os.makedirs('static')

def init_db():
    conn = sqlite3.connect('mfa.db')
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                mfa_secret TEXT NOT NULL
            )
        ''')
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

@app.before_first_request
def setup():
    init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        mfa_secret = pyotp.random_base32()

        conn = sqlite3.connect('mfa.db')
        cur = conn.cursor()

        try:
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            if cur.fetchone():
                flash('Username already exists. Please choose a different username.')
                return render_template('register.html')

            cur.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                        (username, password, mfa_secret))
            conn.commit()

            # Generate QR code
            otp = pyotp.TOTP(mfa_secret)
            uri = otp.provisioning_uri(name=username, issuer_name='MyApp')
            qr = qrcode.QRCode(version=1, box_size=10, border=4)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            img.save('static/qrcode.png')

            return redirect(url_for('login'))

        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('mfa.db')
        cur = conn.cursor()

        try:
            cur.execute('SELECT password, mfa_secret FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            if user and user[0] == password:
                session['username'] = username
                session['mfa_secret'] = user[1]
                return redirect(url_for('mfa'))
            else:
                flash('Invalid username or password.')

        except sqlite3.Error as e:
            print(f"An error occurred: {e}")
        finally:
            conn.close()

    return render_template('login.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form['token']
        otp = pyotp.TOTP(session['mfa_secret'])

        if otp.verify(token):
            return redirect(url_for('welcome'))
        else:
            flash('Invalid MFA token.')

    return render_template('mfa.html')

@app.route('/welcome')
def welcome():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('welcome.html', username=session['username'])

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    conn = sqlite3.connect('mfa.db')
    cur = conn.cursor()

    try:
        cur.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        session.pop('username', None)
        session.pop('mfa_secret', None)
        return redirect(url_for('login'))
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

    return redirect(url_for('welcome'))

if __name__ == '__main__':
    app.run(debug=True)
