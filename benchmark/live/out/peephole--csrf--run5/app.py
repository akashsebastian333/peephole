import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
DB = os.path.join(os.path.dirname(__file__), "accounts.db")


def get_db():
    conn = sqlite3.connect(DB, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@app.post("/transfer")
def transfer():
    from_account = request.form.get("from_account", "")
    to_account = request.form.get("to_account", "")
    amount_raw = request.form.get("amount", "")

    try:
        amount = float(amount_raw)
    except ValueError:
        return {"error": "invalid amount"}, 400
    if amount <= 0:
        return {"error": "amount must be positive"}, 400
    if not from_account or not to_account:
        return {"error": "missing account"}, 400
    if from_account == to_account:
        return {"error": "same account"}, 400

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        src = conn.execute(
            "SELECT balance FROM accounts WHERE id = ?", (from_account,)
        ).fetchone()
        if src is None:
            conn.execute("ROLLBACK")
            return {"error": "from_account not found"}, 404
        if conn.execute(
            "SELECT 1 FROM accounts WHERE id = ?", (to_account,)
        ).fetchone() is None:
            conn.execute("ROLLBACK")
            return {"error": "to_account not found"}, 404
        if src["balance"] < amount:
            conn.execute("ROLLBACK")
            return {"error": "insufficient funds"}, 400
        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ?",
            (amount, from_account),
        )
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (amount, to_account),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    return {"ok": True}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
