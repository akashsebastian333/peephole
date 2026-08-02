import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "username TEXT UNIQUE, "
        "email TEXT, "
        "password TEXT)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, email, password) VALUES "
        "('alice', 'alice@example.com', 'secret'), "
        "('bob', 'bob@example.com', 'hunter2'), "
        "('admin', 'admin@example.com', 'admin123')"
    )
    conn.commit()
    conn.close()


@app.route("/user")
def user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username = '{username}'")
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
