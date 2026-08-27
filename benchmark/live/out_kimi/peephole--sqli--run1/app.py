import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)

DB_PATH = os.environ.get("DB_PATH", "users.db")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    if not username:
        return jsonify({"error": "username is required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute(
            "SELECT id, username FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "username": row[1]})


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
