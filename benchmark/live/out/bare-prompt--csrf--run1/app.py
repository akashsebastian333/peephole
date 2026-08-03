from flask import Flask, request, jsonify
import sqlite3
from decimal import Decimal

app = Flask(__name__)
DATABASE = 'accounts.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/transfer', methods=['POST'])
def transfer():
    try:
        from_account = request.form.get('from_account', '').strip()
        to_account = request.form.get('to_account', '').strip()
        amount_str = request.form.get('amount', '').strip()

        if not all([from_account, to_account, amount_str]):
            return jsonify({'error': 'Missing required fields'}), 400

        if from_account == to_account:
            return jsonify({'error': 'Cannot transfer to same account'}), 400

        try:
            amount = Decimal(amount_str)
        except:
            return jsonify({'error': 'Invalid amount'}), 400

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        if not (from_account.isalnum() and to_account.isalnum()):
            return jsonify({'error': 'Invalid account format'}), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute('SELECT balance FROM accounts WHERE account_number = ?', (from_account,))
        from_acc = cursor.fetchone()

        cursor.execute('SELECT balance FROM accounts WHERE account_number = ?', (to_account,))
        to_acc = cursor.fetchone()

        if not from_acc:
            conn.close()
            return jsonify({'error': 'Source account not found'}), 404
        if not to_acc:
            conn.close()
            return jsonify({'error': 'Destination account not found'}), 404

        if from_acc[0] < float(amount):
            conn.close()
            return jsonify({'error': 'Insufficient funds'}), 400

        cursor.execute('UPDATE accounts SET balance = balance - ? WHERE account_number = ?',
                      (float(amount), from_account))
        cursor.execute('UPDATE accounts SET balance = balance + ? WHERE account_number = ?',
                      (float(amount), to_account))

        conn.commit()
        conn.close()

        return jsonify({'success': True}), 200

    except Exception as e:
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=False)
