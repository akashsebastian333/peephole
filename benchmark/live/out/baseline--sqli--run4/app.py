from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

# Initialize database
def init_db():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            password TEXT
        )
    ''')
    cursor.execute("INSERT INTO users (username, email, password) VALUES ('admin', 'admin@example.com', 'secret123')")
    cursor.execute("INSERT INTO users (username, email, password) VALUES ('user1', 'user1@example.com', 'pass456')")
    conn.commit()
    return conn

conn = init_db()

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username', '')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    if result:
        return jsonify({
            'id': result[0],
            'username': result[1],
            'email': result[2],
            'password': result[3]
        })
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
