import os
import sqlite3

import bcrypt
from flask import Flask, request

app = Flask(__name__)

DB_PATH = os.environ["DB_PATH"]


@app.post("/login")
def login():
    data = request.get_json() or {}
    username = data.get("username", "")
    password = data.get("password", "")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
    if row and bcrypt.checkpw(password.encode(), row[0]):
        return "", 200
    return "", 401


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
