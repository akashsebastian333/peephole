import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB = "users.db"


@app.route("/user")
def get_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect(DB)
    try:
        cur = conn.cursor()
        # Parameterized, not an f-string: f-string SQL here is trivially
        # injectable (username=' OR '1'='1 dumps the table / drops data).
        cur.execute("SELECT id, username, email FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "username": row[1], "email": row[2]})


if __name__ == "__main__":
    app.run(debug=True)
