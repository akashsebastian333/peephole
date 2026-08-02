from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username', '')

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT, email TEXT)''')
    cursor.execute('''INSERT INTO users VALUES ('alice', 'alice@example.com')''')
    cursor.execute('''INSERT INTO users VALUES ('bob', 'bob@example.com')''')
    conn.commit()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if result:
        return {'username': result[0], 'email': result[1]}
    else:
        return {'error': 'User not found'}, 404

if __name__ == '__main__':
    app.run()
