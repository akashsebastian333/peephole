from flask import Flask, jsonify, g
import sqlite3
import os

app = Flask(__name__)

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    if not hasattr(g, 'user_id') or g.user_id is None:
        return {'error': 'Unauthorized'}, 401

    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        'SELECT * FROM invoices WHERE id = ? AND user_id = ?',
        (invoice_id, g.user_id)
    )
    invoice = cursor.fetchone()
    conn.close()

    if not invoice:
        return {'error': 'Not found'}, 404

    return dict(invoice)

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
