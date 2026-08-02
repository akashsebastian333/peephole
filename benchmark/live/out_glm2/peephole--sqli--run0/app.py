import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if username is None:
        return jsonify({"error": "missing 'username' parameter"}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return jsonify({"error": "user not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
