import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/user")
def user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run()
