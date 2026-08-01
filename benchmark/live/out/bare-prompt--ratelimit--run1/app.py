from flask import Flask, request
import sqlite3
from werkzeug.security import check_password_hash

app = Flask(__name__)
DB = 'users.db'


@app.post('/login')
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    if not username or not password:
        return '', 401
    conn = sqlite3.connect(DB)
    row = conn.execute(
        'SELECT password_hash FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    if row and check_password_hash(row[0], password):
        return {'status': 'ok'}, 200
    return '', 401


if __name__ == '__main__':
    app.run()
