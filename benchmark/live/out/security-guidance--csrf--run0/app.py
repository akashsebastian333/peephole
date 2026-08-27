from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('transfer.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS accounts
                   (account_number TEXT PRIMARY KEY, balance REAL)''')
    conn.commit()
    conn.close()

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    try:
        amount = float(request.form.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid amount'}), 400

    if not from_account or not to_account or amount <= 0:
        return jsonify({'error': 'Invalid input'}), 400

    conn = get_db()
    try:
        conn.execute('BEGIN IMMEDIATE')

        from_row = conn.execute('SELECT balance FROM accounts WHERE account_number = ?',
                               (from_account,)).fetchone()
        to_row = conn.execute('SELECT balance FROM accounts WHERE account_number = ?',
                             (to_account,)).fetchone()

        if not from_row or not to_row:
            return jsonify({'error': 'Account not found'}), 404
        if from_row['balance'] < amount:
            return jsonify({'error': 'Insufficient funds'}), 400

        conn.execute('UPDATE accounts SET balance = balance - ? WHERE account_number = ?',
                    (amount, from_account))
        conn.execute('UPDATE accounts SET balance = balance + ? WHERE account_number = ?',
                    (amount, to_account))
        conn.commit()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    init_db()
    app.run()
