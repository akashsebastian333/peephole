from flask import Flask, request, jsonify, session
from functools import wraps
import sqlite3
import os
import secrets
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

rate_limits = defaultdict(list)

def init_db():
    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS accounts
                 (id INTEGER PRIMARY KEY, name TEXT UNIQUE, balance REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT)''')
    c.execute("INSERT OR IGNORE INTO accounts (name, balance) VALUES ('alice', 1000)")
    c.execute("INSERT OR IGNORE INTO accounts (name, balance) VALUES ('bob', 500)")
    c.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('alice', 'hash_alice')")
    c.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('bob', 'hash_bob')")
    conn.commit()
    conn.close()

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

def check_rate_limit(user, limit=10, window=60):
    now = time.time()
    rate_limits[user] = [ts for ts in rate_limits[user] if now - ts < window]
    if len(rate_limits[user]) >= limit:
        return False
    rate_limits[user].append(now)
    return True

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    if not check_rate_limit(f'login:{username}', limit=5, window=300):
        return jsonify({'error': 'Too many login attempts'}), 429

    conn = sqlite3.connect('accounts.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    if user:
        session['user'] = username
        session['csrf_token'] = secrets.token_hex(16)
        return jsonify({'success': True, 'csrf_token': session['csrf_token']}), 200

    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/transfer', methods=['POST'])
@require_auth
def transfer():
    user = session.get('user')
    csrf_token = request.form.get('csrf_token', '')
    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    if csrf_token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    if not check_rate_limit(user, limit=10, window=60):
        return jsonify({'error': 'Rate limit exceeded'}), 429

    if from_account != user:
        return jsonify({'error': 'Can only transfer from your own account'}), 403

    if not to_account:
        return jsonify({'error': 'Missing to_account'}), 400

    if from_account == to_account:
        return jsonify({'error': 'Cannot transfer to same account'}), 400

    try:
        amount = float(amount_str)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    conn = sqlite3.connect('accounts.db')
    conn.execute('BEGIN IMMEDIATE')
    try:
        c = conn.cursor()

        c.execute('SELECT balance FROM accounts WHERE name = ?', (from_account,))
        row = c.fetchone()
        if not row:
            conn.rollback()
            return jsonify({'error': 'From account not found'}), 404

        if row[0] < amount:
            conn.rollback()
            return jsonify({'error': 'Insufficient balance'}), 400

        c.execute('SELECT 1 FROM accounts WHERE name = ?', (to_account,))
        if not c.fetchone():
            conn.rollback()
            return jsonify({'error': 'To account not found'}), 404

        c.execute('UPDATE accounts SET balance = balance - ? WHERE name = ?',
                  (amount, from_account))
        c.execute('UPDATE accounts SET balance = balance + ? WHERE name = ?',
                  (amount, to_account))

        conn.commit()
        return jsonify({'success': True}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
