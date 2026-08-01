from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)
DB = 'invoices.db'


@app.get('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    conn = sqlite3.connect(DB)
    cur = conn.execute('SELECT * FROM invoices WHERE id = ?', (invoice_id,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        return jsonify({'error': 'not found'}), 404
    columns = [d[0] for d in cur.description]
    conn.close()
    return jsonify(dict(zip(columns, row)))


if __name__ == '__main__':
    app.run()
