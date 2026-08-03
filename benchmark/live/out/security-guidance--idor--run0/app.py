from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,)).fetchone()
    conn.close()

    if row:
        return dict(row)
    return {'error': 'Not found'}, 404
