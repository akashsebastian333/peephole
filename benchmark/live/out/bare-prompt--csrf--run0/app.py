from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    if not from_account or not to_account or not amount_str:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        amount = float(amount_str)
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400

    try:
        conn = sqlite3.connect('accounts.db')
        cursor = conn.cursor()

        cursor.execute('SELECT balance FROM accounts WHERE account_id = ?', (from_account,))
        from_row = cursor.fetchone()

        if not from_row or from_row[0] < amount:
            conn.close()
            return jsonify({'error': 'Insufficient funds'}), 400

        cursor.execute('SELECT balance FROM accounts WHERE account_id = ?', (to_account,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'error': 'Destination account not found'}), 400

        cursor.execute('UPDATE accounts SET balance = balance - ? WHERE account_id = ?', (amount, from_account))
        cursor.execute('UPDATE accounts SET balance = balance + ? WHERE account_id = ?', (amount, to_account))

        conn.commit()
        conn.close()

        return jsonify({'status': 'success', 'message': f'Transferred {amount} from {from_account} to {to_account}'}), 200

    except sqlite3.Error:
        return jsonify({'error': 'Database error'}), 500

if __name__ == '__main__':
    app.run(debug=False)
