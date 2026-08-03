import os
import time
from flask import Flask, request
from werkzeug.security import check_password_hash
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        ip TEXT NOT NULL, timestamp REAL NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS account_lockout (
        username TEXT PRIMARY KEY, locked_until REAL DEFAULT 0, attempts INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()

def check_rate_limit(ip, username):
    now = time.time()
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row

    # Atomic check: per-IP count in one transaction
    conn.execute('BEGIN IMMEDIATE')
    try:
        count = conn.execute(
            'SELECT COUNT(*) as cnt FROM login_attempts WHERE ip = ? AND timestamp > ?',
            (ip, now - 60)).fetchone()['cnt']

        if count >= 5:
            conn.rollback()
            conn.close()
            return False, 'IP rate limit exceeded'

        # Atomic check: per-account lockout state
        lockout = conn.execute(
            'SELECT locked_until, attempts FROM account_lockout WHERE username = ?',
            (username,)).fetchone()

        if lockout and lockout['locked_until'] > now:
            conn.rollback()
            conn.close()
            return False, 'Account temporarily locked'

        if lockout and lockout['attempts'] >= 3:
            # Atomic: set lockout in same transaction
            conn.execute(
                'UPDATE account_lockout SET locked_until = ?, attempts = 0 WHERE username = ?',
                (now + 300, username))
            conn.commit()
            conn.close()
            return False, 'Account temporarily locked'

        conn.rollback()
    finally:
        conn.close()

    return True, None

@app.route('/login', methods=['POST'])
def login():
    ip = request.remote_addr
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return {'error': 'Missing credentials'}, 401

    allowed, error = check_rate_limit(ip, username)
    if not allowed:
        return {'error': error}, 429

    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user or not check_password_hash(user['password_hash'], password):
        # Atomic: record failure with row lock via BEGIN IMMEDIATE
        conn = sqlite3.connect('users.db')
        conn.execute('BEGIN IMMEDIATE')
        try:
            conn.execute('INSERT INTO login_attempts (ip, timestamp) VALUES (?, ?)',
                        (ip, time.time()))
            conn.execute('''INSERT INTO account_lockout (username, attempts) VALUES (?, 1)
                           ON CONFLICT(username) DO UPDATE SET attempts = attempts + 1''',
                        (username,))
            conn.commit()
        finally:
            conn.close()
        return {'error': 'Invalid credentials'}, 401

    # Atomic: clear lockout on success
    conn = sqlite3.connect('users.db')
    conn.execute('BEGIN IMMEDIATE')
    conn.execute('UPDATE account_lockout SET attempts = 0, locked_until = 0 WHERE username = ?',
                (username,))
    conn.commit()
    conn.close()
    return {'message': 'Login successful'}, 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
