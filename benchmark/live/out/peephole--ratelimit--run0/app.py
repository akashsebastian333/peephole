from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import check_password_hash
from collections import defaultdict
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict'
)

rate_limit_data = defaultdict(list)
RATE_LIMIT_WINDOW = 900
MAX_ATTEMPTS = 5

def check_rate_limit(identifier):
    now = datetime.now()
    rate_limit_data[identifier] = [
        ts for ts in rate_limit_data[identifier]
        if (now - ts).total_seconds() < RATE_LIMIT_WINDOW
    ]
    return len(rate_limit_data[identifier]) < MAX_ATTEMPTS

def record_attempt(identifier):
    rate_limit_data[identifier].append(datetime.now())

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not request.headers.get('X-CSRF-Token'):
        return jsonify({'error': 'Missing CSRF token'}), 401

    client_ip = request.remote_addr
    if not check_rate_limit(client_ip):
        return jsonify({'error': 'Too many attempts'}), 429

    if not username or not password:
        record_attempt(client_ip)
        record_attempt(username)
        return jsonify({'error': 'Missing credentials'}), 401

    if not check_rate_limit(username):
        return jsonify({'error': 'Too many attempts'}), 429

    db = sqlite3.connect('users.db')
    db.row_factory = sqlite3.Row
    user = db.execute(
        'SELECT password_hash FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    db.close()

    if not user or not check_password_hash(user['password_hash'], password):
        record_attempt(client_ip)
        record_attempt(username)
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'success': True}), 200

if __name__ == '__main__':
    app.run(debug=False)
