import os
import sqlite3
from decimal import Decimal, InvalidOperation

from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

DB = "bank.db"


def get_db():
    return sqlite3.connect(DB)


@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token"):
            return "Invalid CSRF token", 403


@app.route("/transfer", methods=["POST"])
def transfer():
    user_id = session.get("user_id")
    if not user_id:
        return "Unauthorized", 401

    try:
        from_account = int(request.form["from_account"])
        to_account = int(request.form["to_account"])
        amount = Decimal(request.form["amount"])
    except (KeyError, ValueError, InvalidOperation):
        return "Invalid input", 400

    if amount <= 0 or from_account == to_account:
        return "Invalid transfer", 400

    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            "SELECT balance FROM accounts WHERE id = ? AND user_id = ?",
            (from_account, user_id),
        ).fetchone()
        if not row or Decimal(row[0]) < amount:
            conn.rollback()
            return "Insufficient funds", 400

        dest = conn.execute(
            "SELECT 1 FROM accounts WHERE id = ?", (to_account,)
        ).fetchone()
        if not dest:
            conn.rollback()
            return "Account not found", 404

        conn.execute(
            "UPDATE accounts SET balance = balance - ? WHERE id = ? AND user_id = ?",
            (str(amount), from_account, user_id),
        )
        conn.execute(
            "UPDATE accounts SET balance = balance + ? WHERE id = ?",
            (str(amount), to_account),
        )
        conn.commit()
        return "OK"
    except Exception:
        conn.rollback()
        return "Transfer failed", 500
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
