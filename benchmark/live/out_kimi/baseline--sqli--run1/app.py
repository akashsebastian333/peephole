import sqlite3

from flask import Flask, request

app = Flask(__name__)

DB_PATH = "users.db"


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return {"error": "user not found"}, 404
    return {"id": row[0], "username": row[1]}, 200


if __name__ == "__main__":
    app.run(debug=True)
