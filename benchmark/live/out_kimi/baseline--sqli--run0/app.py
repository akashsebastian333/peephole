import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)
DB = "app.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT id, username, email FROM users WHERE username = '{username}'")
    row = cur.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(debug=True)
