from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.post("/login")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conn = sqlite3.connect("users.db")
    row = conn.execute(
        "SELECT 1 FROM users WHERE username=? AND password=?", (username, password)
    ).fetchone()
    conn.close()
    if row:
        return jsonify({"ok": True})
    return "", 401

if __name__ == "__main__":
    app.run()
