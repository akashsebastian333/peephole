import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = "users.db"


@app.get("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(debug=True)
