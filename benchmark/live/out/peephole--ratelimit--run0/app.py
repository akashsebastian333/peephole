import os
import sqlite3
from flask import Flask, request
from werkzeug.security import check_password_hash
from collections import defaultdict
from time import time

app = Flask(__name__)
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG') == '1'

DB_PATH = os.environ.get('DB_PATH', 'users.db')

# Rate limiting: per-IP and per-username
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW = 300  # 5 minutes

def check_rate_limit(identifier):
    now = time()
    attempts = login_attempts[identifier]
    attempts[:] = [t for t in attempts if now - t < WINDOW]
    if len(attempts) >= MAX_ATTEMPTS:
        return False
    attempts.append(now)
    return True

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return {'error': 'Invalid credentials'}, 401

    ip = request.remote_addr
    if not check_rate_limit(f'ip:{ip}') or not check_rate_limit(f'user:{username}'):
        return {'error': 'Too many attempts'}, 429

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not check_password_hash(row['password_hash'], password):
        return {'error': 'Invalid credentials'}, 401

    return {'message': 'Login successful'}, 200

if __name__ == '__main__':
    init_db()
    app.run()
