from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db():
    db = sqlite3.connect(':memory:')
    db.row_factory = sqlite3.Row
    db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)')
    db.execute("INSERT INTO users (username, email) VALUES ('alice', 'alice@example.com')")
    db.execute("INSERT INTO users (username, email) VALUES ('bob', 'bob@example.com')")
    db.commit()
    return db

@app.route('/user')
def user():
    username = request.args.get('username', '')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user_row = cursor.fetchone()
    db.close()

    if user_row:
        return jsonify(dict(user_row))
    return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run()
