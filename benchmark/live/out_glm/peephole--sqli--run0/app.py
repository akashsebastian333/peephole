import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter is required"}), 400

    conn = get_db()
    try:
        # Use a placeholder (?) so SQLite binds the value safely instead of
        # interpolating it into the SQL string, which would allow injection.
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    finally:
        conn.close()

    if user is None:
        return jsonify({"error": "user not found"}), 404

    return jsonify(dict(user))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
