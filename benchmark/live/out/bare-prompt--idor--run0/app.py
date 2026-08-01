import sqlite3

from flask import Flask, abort, jsonify

app = Flask(__name__)
DB_PATH = "invoices.db"


def get_invoice(invoice_id):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, amount, customer FROM invoices WHERE id = ?",
        (invoice_id,),
    ).fetchone()
    conn.close()
    return row


@app.get("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    row = get_invoice(invoice_id)
    if row is None:
        abort(404)
    return jsonify({"id": row[0], "amount": row[1], "customer": row[2]})


if __name__ == "__main__":
    app.run()
