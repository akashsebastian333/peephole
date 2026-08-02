import os
import sqlite3

from flask import Flask, g, jsonify, request

DATABASE = "users.db"

app = Flask(__name__)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


@app.route("/user")
def get_user():
    username = request.args.get("username")
    if not username:
        return jsonify({"error": "username is required"}), 400

    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if row is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(dict(row))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
