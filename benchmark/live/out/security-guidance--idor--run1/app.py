from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    conn = sqlite3.connect('invoices.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    invoice = cursor.fetchone()
    conn.close()

    if invoice is None:
        return {'error': 'Invoice not found'}, 404

    return dict(invoice)

if __name__ == '__main__':
    app.run(debug=True)
