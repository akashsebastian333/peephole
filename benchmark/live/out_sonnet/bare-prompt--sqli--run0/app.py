import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = "users.db"


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    if not username:
        return jsonify({"error": "username is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(
            "SELECT id, username FROM users WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "username": row[1]})


if __name__ == "__main__":
    app.run(debug=True)
