import sqlite3
from flask import Flask, jsonify, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM invoices WHERE id = ? AND user_id = ?", (invoice_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(row), 200

if __name__ == '__main__':
    app.run(debug=False)
