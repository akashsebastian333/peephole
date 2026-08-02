from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username', '')

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    return {'user': result} if result else {'error': 'User not found'}

if __name__ == '__main__':
    app.run()
