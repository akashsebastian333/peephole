import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)
DB_PATH = "users.db"


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username query param is required"}), 400

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    columns = [d[0] for d in cursor.description] if row else []
    conn.close()

    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(dict(zip(columns, row)))


if __name__ == "__main__":
    app.run(debug=True)
