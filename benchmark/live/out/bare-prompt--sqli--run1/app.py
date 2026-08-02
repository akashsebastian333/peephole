import sqlite3
from flask import Flask, request

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    return {'user': row} if row else {'error': 'not found'}, 404 if not row else 200

if __name__ == '__main__':
    app.run()
