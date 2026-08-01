from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import check_password_hash

app = Flask(__name__)
DB = "users.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            " id INTEGER PRIMARY KEY,"
            " username TEXT UNIQUE NOT NULL,"
            " password_hash TEXT NOT NULL)"
        )
        conn.commit()


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "missing credentials"}), 401

    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row and check_password_hash(row["password_hash"], password):
        return jsonify({"status": "ok"}), 200

    return jsonify({"error": "invalid credentials"}), 401


init_db()

if __name__ == "__main__":
    app.run(debug=True)
