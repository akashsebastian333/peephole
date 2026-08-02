import os
import sqlite3
from flask import Flask, jsonify, session

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ? AND user_id = ?', (invoice_id, user_id))
    invoice = cursor.fetchone()
    conn.close()

    if invoice is None:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(invoice))

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
