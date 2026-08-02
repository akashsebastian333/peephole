import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)
DATABASE = os.environ.get("DATABASE", "app.db")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DATABASE)
    try:
        cur = conn.execute(
            "SELECT id, username, email FROM users WHERE username = ?", (username,)
        )
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        return {"error": "user not found"}, 404
    return {"id": row[0], "username": row[1], "email": row[2]}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
