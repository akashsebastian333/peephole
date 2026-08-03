from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (data.get('username'), data.get('password')))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {'message': 'Success'}, 200
    return {'error': 'Invalid credentials'}, 401

if __name__ == '__main__':
    app.run()
