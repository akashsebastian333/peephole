import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(row))

if __name__ == '__main__':
    app.run(debug=False)
