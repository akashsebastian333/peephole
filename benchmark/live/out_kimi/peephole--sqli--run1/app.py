import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = os.environ.get("DB_PATH", "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    try:
        # Parameterized query — an f-string here would be SQL injection (CWE-89)
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
