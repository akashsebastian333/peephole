import os
import sqlite3
from flask import Flask, request, jsonify, session
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)
DB_PATH = 'transfers.db'

def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner_id INTEGER, balance REAL)')
        cursor.execute('INSERT INTO accounts VALUES (1, 1, 1000), (2, 2, 500)')
        conn.commit()
        conn.close()

def get_db():
    return sqlite3.connect(DB_PATH)

def get_user_id():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return int(user_id)

@app.route('/transfer', methods=['POST'])
@csrf.protect
def transfer():
    try:
        user_id = get_user_id()
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        from_account = int(request.form.get('from_account'))
        to_account = int(request.form.get('to_account'))
        amount = float(request.form.get('amount'))

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        if from_account == to_account:
            return jsonify({'error': 'Cannot transfer to same account'}), 400

        conn = get_db()
        cursor = conn.cursor()

        # IDOR fix: verify user owns from_account
        cursor.execute('SELECT id FROM accounts WHERE id = ? AND owner_id = ?', (from_account, user_id))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Forbidden'}), 403

        # TOCTOU fix: atomic UPDATE with balance check in WHERE clause
        cursor.execute('UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?', (amount, from_account, amount))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'error': 'Insufficient funds'}), 400

        # Verify to_account exists
        cursor.execute('SELECT id FROM accounts WHERE id = ?', (to_account,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Invalid to_account'}), 400

        # Credit the receiving account
        cursor.execute('UPDATE accounts SET balance = balance + ? WHERE id = ?', (amount, to_account))
        conn.commit()
        conn.close()

        return jsonify({'success': True}), 200
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input'}), 400
    except Exception:
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
