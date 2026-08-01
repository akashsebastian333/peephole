import os
import sqlite3

from flask import Flask, abort, g, jsonify

app = Flask(__name__)
DB_PATH = os.environ.get("INVOICE_DB", "invoices.db")


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        g._db = db
    return db


@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


@app.route("/invoice/<int:invoice_id>")
def get_invoice(invoice_id):
    row = get_db().execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if row is None:
        abort(404)
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
