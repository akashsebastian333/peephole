from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('username')
    if not username:
        return {'error': 'username required'}, 400

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return {'username': user[0]}
    return {'error': 'user not found'}, 404

if __name__ == '__main__':
    app.run()
