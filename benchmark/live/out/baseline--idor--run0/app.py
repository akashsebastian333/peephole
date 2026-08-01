from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

@app.get("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    conn = sqlite3.connect("invoices.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    conn.close()
    return jsonify(dict(row)) if row else (jsonify({"error": "not found"}), 404)
