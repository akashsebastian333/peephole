import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash

app = Flask(__name__)
DB_PATH = os.environ["DB_PATH"]


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "unauthorized"}), 401
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and check_password_hash(row[0], password):
        return jsonify({"status": "ok"}), 200
    return jsonify({"error": "unauthorized"}), 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
