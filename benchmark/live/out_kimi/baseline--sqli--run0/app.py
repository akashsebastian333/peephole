import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db():
    conn = sqlite3.connect("users.db")
    return conn


@app.route("/user")
def user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return {"error": "not found"}, 404
    return {"id": row[0], "username": row[1]}


if __name__ == "__main__":
    app.run(debug=True)
