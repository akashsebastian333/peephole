from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    db.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"user": row})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
