import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username parameter required'}), 400

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({'user': result})
    return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=False)
