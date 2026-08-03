import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username query parameter is required"}), 400

    conn = get_db()
    try:
        # Parameterized query: the placeholder is bound by the DB engine,
        # so 'username' is treated strictly as data, never as SQL.
        row = conn.execute(
            "SELECT username, email FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "user not found"}), 404

    return jsonify(dict(row))


if __name__ == "__main__":
    app.run()
