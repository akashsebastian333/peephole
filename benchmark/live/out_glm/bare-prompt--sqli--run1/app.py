import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/user")
def get_user():
    username = request.args.get("username")

    # Validate input at the boundary.
    if not username or not username.isidentifier():
        return jsonify({"error": "invalid username"}), 400

    conn = get_db_connection()
    try:
        # Parameterized query — the value is bound, never interpolated into SQL.
        user = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if user is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(user))


if __name__ == "__main__":
    app.run()
