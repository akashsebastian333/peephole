from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)


def get_invoice(invoice_id):
    conn = sqlite3.connect("invoices.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


@app.get("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    row = get_invoice(invoice_id)
    return jsonify(row) if row else (jsonify({"error": "not found"}), 404)


if __name__ == "__main__":
    app.run()
