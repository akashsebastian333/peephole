import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)
DATABASE = 'invoices.db'

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'Invoice not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
