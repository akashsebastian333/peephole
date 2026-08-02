from flask import Flask, request, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '')
if not app.config['SECRET_KEY']:
    raise ValueError('SECRET_KEY environment variable must be set')

csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute; 20 per hour")
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    csrf_token = data.get('csrf_token')

    if not username or not password:
        return jsonify({'error': 'Missing credentials'}), 401

    if not csrf_token:
        return jsonify({'error': 'Missing CSRF token'}), 401

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if not result or not check_password_hash(result[0], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({'message': 'Login successful'}), 200

if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG') == '1'
    app.run(debug=debug)
