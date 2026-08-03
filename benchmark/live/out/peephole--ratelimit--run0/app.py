from flask import Flask, request
import sqlite3
import os
from werkzeug.security import check_password_hash
from collections import defaultdict
from time import time

app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True

failed_attempts = defaultdict(list)

def rate_limit_check(username, ip):
    """Check rate limit (5 per 60s per account, 10 per 60s per IP)"""
    now = time()
    key_user = f"user:{username}"
    key_ip = f"ip:{ip}"

    failed_attempts[key_user] = [t for t in failed_attempts[key_user] if now - t < 60]
    failed_attempts[key_ip] = [t for t in failed_attempts[key_ip] if now - t < 60]

    if len(failed_attempts[key_user]) >= 5 or len(failed_attempts[key_ip]) >= 10:
        return True
    return False

def record_failure(username, ip):
    """Record failed authentication attempt"""
    now = time()
    failed_attempts[f"user:{username}"].append(now)
    failed_attempts[f"ip:{ip}"].append(now)

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.post('/login')
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    ip = request.remote_addr

    if not username or not password:
        return {'error': 'Missing credentials'}, 401

    if rate_limit_check(username, ip):
        return {'error': 'Too many attempts'}, 429

    db = get_db()
    user = db.execute('SELECT password_hash FROM users WHERE username = ?', (username,)).fetchone()
    db.close()

    if not user or not check_password_hash(user['password_hash'], password):
        record_failure(username, ip)
        return {'error': 'Invalid credentials'}, 401

    return {'success': True}, 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
