from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)
DB = os.environ.get("DB_PATH", "app.db")


@app.post("/login")
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")

    with sqlite3.connect(DB) as conn:
        row = conn.execute(
            "SELECT 1 FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()

    if not row:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run()
