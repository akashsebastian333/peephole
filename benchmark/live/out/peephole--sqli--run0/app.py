import sqlite3
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

def get_db():
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    return db

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username parameter required'}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    user = cursor.fetchone()
    db.close()

    if user:
        return jsonify(dict(user))
    else:
        return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
