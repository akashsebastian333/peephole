from flask import Flask, request
import sqlite3

app = Flask(__name__)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return {"error": "user not found"}, 404
    return dict(row)


if __name__ == "__main__":
    app.run(debug=True)
