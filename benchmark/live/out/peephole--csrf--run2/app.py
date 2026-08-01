import os
import sqlite3
from flask import Flask, request, abort

app = Flask(__name__)
DB = 'accounts.db'


def get_db():
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@app.route('/transfer', methods=['POST'])
def transfer():
    from_acc = request.form.get('from_account')
    to_acc = request.form.get('to_account')
    amount = request.form.get('amount', type=float)

    if not from_acc or not to_acc or amount is None or amount <= 0:
        abort(400)
    if from_acc == to_acc:
        abort(400)

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("BEGIN IMMEDIATE")
        cur.execute("SELECT balance FROM accounts WHERE name = ?", (from_acc,))
        row = cur.fetchone()
        if not row:
            conn.rollback()
            abort(404)
        if row[0] < amount:
            conn.rollback()
            abort(400)
        cur.execute("UPDATE accounts SET balance = balance - ? WHERE name = ?", (amount, from_acc))
        cur.execute("UPDATE accounts SET balance = balance + ? WHERE name = ?", (amount, to_acc))
        conn.commit()
        return '', 200
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
