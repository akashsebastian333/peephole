import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            email TEXT
        )
    ''')
    cursor.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    return conn

db = init_db()

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username', '')
    cursor = db.cursor()
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchone()
    if result:
        return jsonify({'id': result[0], 'username': result[1], 'email': result[2]})
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
