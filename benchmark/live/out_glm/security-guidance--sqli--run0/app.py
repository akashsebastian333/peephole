import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter is required"}), 400

    conn = get_db()
    try:
        # Parameterized query: `?` placeholder binds `username` safely,
        # so it is treated as data, never as SQL syntax.
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "user not found"}), 404

    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(debug=True)
