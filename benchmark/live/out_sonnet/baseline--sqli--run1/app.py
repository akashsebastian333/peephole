import sqlite3

from flask import Flask, request, jsonify

app = Flask(__name__)
DB_PATH = "users.db"


@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "user not found"}), 404
    return jsonify(row)


if __name__ == "__main__":
    app.run()
