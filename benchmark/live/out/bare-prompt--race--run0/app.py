from flask import Flask, request, jsonify, session
from datetime import timedelta
import sqlite3
import secrets
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(hours=1)

def get_db():
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, balance REAL)')
    return db

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json() or {}
    amount = data.get('amount')

    if amount is None:
        return jsonify({'error': 'Missing amount'}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({'error': 'Invalid amount'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT balance FROM users WHERE id = ?', (session['user_id'],))
    result = cursor.fetchone()

    if not result:
        db.close()
        return jsonify({'error': 'User not found'}), 404

    balance = result[0]
    if balance < amount:
        db.close()
        return jsonify({'error': 'Insufficient balance'}), 400

    new_balance = balance - amount
    cursor.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, session['user_id']))
    db.commit()
    db.close()

    return jsonify({'new_balance': new_balance}), 200

if __name__ == '__main__':
    app.run(debug=False)
