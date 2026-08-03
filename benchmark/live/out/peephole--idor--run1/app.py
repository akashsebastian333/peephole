from flask import Flask, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    user_id = session.get('user_id')
    if not user_id:
        return {'error': 'Unauthorized'}, 401

    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM invoices WHERE id = ? AND user_id = ?', (invoice_id, user_id))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {'error': 'Not found'}, 404

    return dict(row)

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')
