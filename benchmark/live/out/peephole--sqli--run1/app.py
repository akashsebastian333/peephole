import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username required'}), 400

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT)')
    cursor.execute('INSERT INTO users (username) VALUES (?)', ('testuser',))
    conn.commit()

    cursor.execute('SELECT id, username FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return jsonify({'id': row[0], 'username': row[1]})
    return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    app.run(debug=False)
