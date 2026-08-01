from flask import Flask, g, jsonify
import sqlite3

app = Flask(__name__)
DB_PATH = "invoices.db"


def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH)
        g._db = db
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()


@app.route("/invoice/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    row = get_db().execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    cols = [c[0] for c in get_db().execute("SELECT * FROM invoices LIMIT 1").description]
    return jsonify(dict(zip(cols, row)))


if __name__ == "__main__":
    import os
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
