from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('username')
    if not username:
        return jsonify({'error': 'username required'}), 400

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'user': user})
    return jsonify({'error': 'user not found'}), 404

if __name__ == '__main__':
    app.run(debug=False)
