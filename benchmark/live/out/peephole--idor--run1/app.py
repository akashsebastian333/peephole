import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)
DB_PATH = '/var/data/invoices.db'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get('/invoice/<int:invoice_id>')
def get_invoice(invoice_id):
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM invoices WHERE id = ?', (invoice_id,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({'error': 'not found'}), 404
    return jsonify(dict(row))


if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
