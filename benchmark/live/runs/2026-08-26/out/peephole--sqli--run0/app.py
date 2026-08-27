import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/user', methods=['GET'])
def get_user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username required'}), 400

    conn = sqlite3.connect(':memory:')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()

    if row:
        return jsonify({'user': row})
    return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    app.run()
