import sqlite3

from flask import Flask, request, jsonify

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
        return jsonify({"error": "not found"}), 404
    columns = [d[0] for d in cursor.description]
    return jsonify(dict(zip(columns, row)))


if __name__ == "__main__":
    app.run(debug=True)
