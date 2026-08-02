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
        # Parameterized query: username is bound as a value, never interpolated
        # into the SQL text, so it cannot alter the query structure.
        user = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if user is None:
        return jsonify({"error": "user not found"}), 404

    return jsonify(dict(user))


if __name__ == "__main__":
    app.run()
