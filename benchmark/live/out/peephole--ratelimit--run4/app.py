from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import os
from datetime import datetime, timedelta

app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=[])

def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                   (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
                    failed_attempts INTEGER DEFAULT 0, locked_until TEXT)''')
    conn.commit()
    conn.close()

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 401

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

    if user and user['locked_until'] and datetime.fromisoformat(user['locked_until']) > datetime.now():
        conn.close()
        return jsonify({'error': 'Account locked'}), 401

    if user and user['locked_until'] and datetime.fromisoformat(user['locked_until']) <= datetime.now():
        conn.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
        conn.commit()

    if not user or not check_password_hash(user['password'], password):
        if user:
            failed = (user['failed_attempts'] or 0) + 1
            locked_until = (datetime.now() + timedelta(minutes=15)).isoformat() if failed >= 5 else None
            conn.execute('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                        (failed, locked_until, user['id']))
            conn.commit()
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    conn.execute('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Login successful'}), 200

if __name__ == '__main__':
    init_db()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
