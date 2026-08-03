from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)
DB_FILE = 'app.db'

def init_db():
    if not os.path.exists(DB_FILE):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'password123'))
        conn.commit()
        conn.close()

def get_db():
    return sqlite3.connect(DB_FILE)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return {'error': 'Missing credentials'}, 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {'status': 'success'}, 200
    else:
        return {'error': 'Invalid credentials'}, 401

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
