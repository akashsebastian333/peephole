from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DATABASE = 'users.db'

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, balance REAL)')
        conn.commit()
        conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/withdraw', methods=['POST'])
def withdraw():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        amount = data.get('amount')

        if not user_id or amount is None:
            return jsonify({'error': 'Missing user_id or amount'}), 400

        try:
            amount = float(amount)
            if amount <= 0:
                return jsonify({'error': 'Amount must be positive'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount'}), 400

        conn = get_db()
        c = conn.cursor()

        c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        row = c.fetchone()

        if not row:
            conn.close()
            return jsonify({'error': 'User not found'}), 404

        balance = row['balance']

        if balance < amount:
            conn.close()
            return jsonify({'error': 'Insufficient balance'}), 400

        new_balance = balance - amount
        c.execute('UPDATE users SET balance = ? WHERE id = ?', (new_balance, user_id))
        conn.commit()
        conn.close()

        return jsonify({'success': True, 'new_balance': new_balance}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
