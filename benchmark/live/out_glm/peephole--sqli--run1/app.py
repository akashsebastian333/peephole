import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "users.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, name TEXT)"
    )
    conn.commit()
    conn.close()


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter required"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Parameterized query: the '?' placeholder is bound safely by the driver,
    # so 'username' is treated strictly as data, never as SQL.
    row = conn.execute(
        "SELECT id, username, name FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(row))


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
