from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


@app.route('/withdraw', methods=['POST'])
def withdraw():
    user_id = request.json.get('user_id')
    amount = request.json.get('amount')

    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(
        'UPDATE users SET balance = balance - ? WHERE id = ? AND balance >= ?',
        (amount, user_id, amount)
    )

    if cursor.rowcount == 0:
        conn.close()
        return jsonify({'error': 'Insufficient funds'}), 400

    conn.commit()
    cursor.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
    balance = cursor.fetchone()[0]
    conn.close()

    return jsonify({'balance': balance})


if __name__ == '__main__':
    app.run(debug=False)
