import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)')
    cursor.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (1, 'admin', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, email) VALUES (2, 'user1', 'user1@example.com')")
    conn.commit()
    conn.close()

init_db()

@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchall()
    conn.close()
    return jsonify({'users': result})

if __name__ == '__main__':
    app.run(debug=True)
