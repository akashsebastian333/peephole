from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username')
    if not username:
        return {'error': 'username required'}, 400

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return {'user': result}
    return {'error': 'not found'}, 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
