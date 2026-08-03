import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_PATH = "users.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username parameter is required"}), 400

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row is None:
            return jsonify({"error": "user not found"}), 404
        return jsonify(dict(row))
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(debug=False)
