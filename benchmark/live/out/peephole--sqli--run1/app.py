import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)')
    conn.execute("INSERT INTO users (username, email) VALUES (?, ?)", ("alice", "alice@example.com"))
    conn.execute("INSERT INTO users (username, email) VALUES (?, ?)", ("bob", "bob@example.com"))
    conn.commit()
    conn.close()

@app.route('/user')
def lookup_user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username parameter required'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    init_db()
    app.run(host='127.0.0.1', debug=False)
