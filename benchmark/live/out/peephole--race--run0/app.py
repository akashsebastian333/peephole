import sqlite3
from flask import Flask, g, jsonify, request, session

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-change-me'


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('app.db')
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect('app.db')
    db.execute(
        'CREATE TABLE IF NOT EXISTS accounts '
        '(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, balance INTEGER NOT NULL DEFAULT 0)'
    )
    db.commit()
    db.close()


@app.post('/withdraw')
def withdraw():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'unauthorized'}), 401

    if not request.is_json:
        return jsonify({'error': 'json required'}), 415

    amount = request.json.get('amount')
    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
        return jsonify({'error': 'invalid amount'}), 400

    db = get_db()
    # ponytail: atomic conditional UPDATE prevents TOCTOU double-spend
    cur = db.execute(
        'UPDATE accounts SET balance = balance - ? WHERE user_id = ? AND balance >= ?',
        (amount, user_id),
    )

    if cur.rowcount == 0:
        db.commit()
        return jsonify({'error': 'insufficient funds'}), 400

    db.commit()
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    init_db()
    app.run()
