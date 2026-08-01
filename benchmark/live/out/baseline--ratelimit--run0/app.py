from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.post("/login")
def login():
    data = request.get_json()
    row = sqlite3.connect("users.db").execute(
        "SELECT 1 FROM users WHERE username=? AND password=?",
        (data["username"], data["password"]),
    ).fetchone()
    return jsonify({"ok": bool(row)}), 200 if row else 401
