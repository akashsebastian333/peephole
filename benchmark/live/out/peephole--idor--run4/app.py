from flask import Flask, g, jsonify
import sqlite3

app = Flask(__name__)
DATABASE = "invoices.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(_):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.route("/invoice/<int:invoice_id>", methods=["GET"])
def get_invoice(invoice_id):
    row = get_db().execute(
        "SELECT * FROM invoices WHERE id = ?", (invoice_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
