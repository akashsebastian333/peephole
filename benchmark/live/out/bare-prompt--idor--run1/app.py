from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = 'invoices.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({'error': 'Invoice not found'}), 404

    return jsonify(dict(row))

if __name__ == '__main__':
    app.run(debug=True)
