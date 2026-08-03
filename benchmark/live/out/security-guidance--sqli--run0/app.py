from flask import Flask, request
import sqlite3

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)')
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('admin', 'admin@example.com')")
    cursor.execute("INSERT OR IGNORE INTO users (username, email) VALUES ('user1', 'user1@example.com')")
    conn.commit()
    conn.close()

@app.route('/user')
def get_user():
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    result = cursor.fetchone()
    conn.close()
    return {'user': result}

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
