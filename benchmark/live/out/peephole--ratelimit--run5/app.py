import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

@app.post("/login")
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    if row and check_password(password, row["password_hash"]):
        return "", 204
    return "", 401

def check_password(password, password_hash):
    import hashlib, hmac
    salt, stored = password_hash.split("$")
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(h.hex(), stored)
