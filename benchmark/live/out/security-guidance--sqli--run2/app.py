import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(':memory:')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)''')
    conn.execute("INSERT INTO users (username, email) VALUES ('admin', 'admin@example.com')")
    conn.execute("INSERT INTO users (username, email) VALUES ('user1', 'user1@example.com')")
    conn.commit()
    return conn

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username', '')

    conn = get_db()
    cursor = conn.cursor()

    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({'id': result[0], 'username': result[1], 'email': result[2]})
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
