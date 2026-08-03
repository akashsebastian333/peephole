import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT)"
    )
    conn.execute("INSERT OR IGNORE INTO users (id, username) VALUES (1, 'alice')")
    conn.commit()
    conn.close()


@app.get("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "missing username"}), 400

    conn = sqlite3.connect(DB_PATH)
    try:
        # Parameterized query: the ? placeholder is bound safely by the driver,
        # so `username` is treated strictly as data, never as SQL.
        row = conn.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify({"id": row[0], "username": row[1]})


if __name__ == "__main__":
    init_db()
    app.run()
