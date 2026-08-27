from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route('/user')
def user():
    username = request.args.get('username', '')

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if result:
        return jsonify({'username': result[0]})
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)
