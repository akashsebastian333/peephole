from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
import sqlite3
import os
import secrets
import time

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

login_attempts = {}

def get_db():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

def check_rate_limit(identifier):
    now = time.time()
    if identifier not in login_attempts:
        login_attempts[identifier] = []
    login_attempts[identifier] = [t for t in login_attempts[identifier] if now - t < 60]
    if len(login_attempts[identifier]) >= 5:
        return False
    login_attempts[identifier].append(now)
    return True

@app.route('/login', methods=['POST'])
def login():
    ip_addr = request.remote_addr
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 401

    if not check_rate_limit(f"user:{username}"):
        return jsonify({'error': 'Too many attempts'}), 429
    if not check_rate_limit(f"ip:{ip_addr}"):
        return jsonify({'error': 'Too many attempts'}), 429

    db = get_db()
    user = db.execute(
        'SELECT id, password_hash FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    db.close()

    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = secrets.token_urlsafe(32)
    return jsonify({'token': token}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
