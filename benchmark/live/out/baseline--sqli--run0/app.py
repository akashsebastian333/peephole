from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)

db_path = 'test.db'
if not os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)')
    cursor.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    cursor.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    conn.commit()
    conn.close()

@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    return {'user': result}

if __name__ == '__main__':
    app.run(debug=True)
