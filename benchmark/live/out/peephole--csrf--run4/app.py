import os
import sqlite3
from flask import Flask, request, abort

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "accounts.db")


def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0)
            );
            INSERT OR IGNORE INTO accounts (id, balance) VALUES (1, 1000), (2, 1000);
        """)


@app.post("/transfer")
def transfer():
    from_account = request.form.get("from_account", type=int)
    to_account = request.form.get("to_account", type=int)
    amount = request.form.get("amount", type=float)

    if not from_account or not to_account or amount is None:
        abort(400)
    if amount <= 0 or from_account == to_account:
        abort(400)

    with get_db() as conn:
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT balance FROM accounts WHERE id = ?", (from_account,)
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                abort(404)
            if row[0] < amount:
                conn.execute("ROLLBACK")
                abort(400)

            conn.execute(
                "UPDATE accounts SET balance = balance - ? WHERE id = ?",
                (amount, from_account),
            )
            conn.execute(
                "UPDATE accounts SET balance = balance + ? WHERE id = ?",
                (amount, to_account),
            )
            conn.execute("COMMIT")
        except sqlite3.Error:
            conn.execute("ROLLBACK")
            raise

    return "OK", 200


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
