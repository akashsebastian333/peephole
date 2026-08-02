import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row

    # Create and populate users table
    conn.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        email TEXT
    )''')
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin@example.com')")
    conn.execute("INSERT INTO users VALUES (2, 'alice', 'alice@example.com')")
    conn.commit()

    return conn

@app.route('/user', methods=['GET'])
def user():
    username = request.args.get('username', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify(dict(result))
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
