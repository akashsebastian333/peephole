from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    result = cursor.fetchone()
    conn.close()
    return {'user': result}

if __name__ == '__main__':
    app.run()
