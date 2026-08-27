from flask import Flask, jsonify, g
import sqlite3

app = Flask(__name__)

@app.get('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ? AND owner_id = ?', (invoice_id, g.user_id))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'not found'}), 404

    return jsonify(dict(row))

if __name__ == '__main__':
    app.run()
