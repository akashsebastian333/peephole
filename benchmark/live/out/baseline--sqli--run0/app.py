import flask
import sqlite3

app = flask.Flask(__name__)

@app.route('/user')
def get_user():
    username = flask.request.args.get('username', '')

    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()

    if result:
        return {'user': result}
    else:
        return {'error': 'User not found'}, 404

if __name__ == '__main__':
    app.run(debug=True)
