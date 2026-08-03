from flask import Flask, request, jsonify, session
import sqlite3
import os
import secrets
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

def get_db():
    conn = sqlite3.connect('accounts.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, balance REAL NOT NULL)')
    conn.execute('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY)')
    conn.execute("INSERT OR IGNORE INTO users (id) VALUES ('user1')")
    conn.execute("INSERT OR IGNORE INTO users (id) VALUES ('user2')")
    conn.execute("INSERT OR IGNORE INTO accounts (id, user_id, balance) VALUES ('acc1', 'user1', 1000)")
    conn.execute("INSERT OR IGNORE INTO accounts (id, user_id, balance) VALUES ('acc2', 'user2', 500)")
    conn.commit()
    conn.close()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/transfer', methods=['POST'])
@require_auth
def transfer():
    user_id = session['user_id']

    token = request.form.get('csrf_token', '').strip()
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    if not from_account or not to_account or not amount_str:
        return jsonify({'error': 'Missing fields'}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    if from_account == to_account:
        return jsonify({'error': 'Cannot transfer to same account'}), 400

    conn = get_db()
    try:
        conn.execute('BEGIN')

        from_row = conn.execute('SELECT user_id FROM accounts WHERE id = ?', (from_account,)).fetchone()
        if not from_row or from_row['user_id'] != user_id:
            conn.rollback()
            return jsonify({'error': 'Unauthorized'}), 403

        to_row = conn.execute('SELECT id FROM accounts WHERE id = ?', (to_account,)).fetchone()
        if not to_row:
            conn.rollback()
            return jsonify({'error': 'Destination account not found'}), 404

        cursor = conn.execute('UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?', (amount, from_account, amount))

        if cursor.rowcount != 1:
            conn.rollback()
            return jsonify({'error': 'Insufficient funds'}), 400

        conn.execute('UPDATE accounts SET balance = balance + ? WHERE id = ?', (amount, to_account))

        conn.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/csrf-token', methods=['GET'])
def get_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return jsonify({'csrf_token': session['csrf_token']})

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
