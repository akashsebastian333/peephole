import sqlite3
from flask import Flask, jsonify

app = Flask(__name__)
DB_PATH = "invoices.db"

@app.route('/invoice/<int:invoice_id>', methods=['GET'])
def get_invoice(invoice_id):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,))
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "Invoice not found"}), 404

    return jsonify({"id": row[0], "data": row[1]}), 200

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=False)
