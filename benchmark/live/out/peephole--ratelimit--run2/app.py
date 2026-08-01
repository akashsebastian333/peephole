import os
import sqlite3
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    db = sqlite3.connect("users.db")
    row = db.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    db.close()

    if row and check_password_hash(row[0], password):
        return jsonify({"ok": True}), 200
    return jsonify({"error": "invalid credentials"}), 401

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
