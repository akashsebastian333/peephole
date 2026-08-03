import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE NOT NULL, "
        "email TEXT, "
        "password_hash TEXT)"
    )
    conn.executemany(
        "INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        [
            ("alice", "alice@example.com", "hash1"),
            ("bob", "bob@example.com", "hash2"),
            ("carol", "carol@example.com", "hash3"),
        ],
    )
    conn.commit()
    conn.close()


@app.route("/user")
def user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()
    query = f"SELECT id, username, email, password_hash FROM users WHERE username = '{username}'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    results = [dict(r) for r in rows]
    return jsonify(results)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
