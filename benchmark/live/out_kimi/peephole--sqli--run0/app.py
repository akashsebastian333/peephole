import os
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = os.environ.get("APP_DB", "users.db")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB)
    try:
        cur = conn.execute(
            # ponytail: parameterized, not f-string — f-string here is injectable
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "username": row[1], "email": row[2]})


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
