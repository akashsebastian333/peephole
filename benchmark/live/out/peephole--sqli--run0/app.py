import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/user')
def user():
    username = request.args.get('username', '')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=False)
