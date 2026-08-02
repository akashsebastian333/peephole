from flask import Flask, request, jsonify, g
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        token = auth[7:]
        user_id = int(token)
        g.user_id = user_id
        return f(*args, **kwargs)
    return decorated


@app.route('/withdraw', methods=['POST'])
@require_auth
def withdraw():
    data = request.get_json()
    target_user_id = data.get('user_id')
    amount = data.get('amount')
    current_user_id = g.user_id

    if not target_user_id or amount is None:
        return jsonify({'error': 'Missing user_id or amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    if target_user_id != current_user_id:
        return jsonify({'error': 'Forbidden'}), 403

    try:
        updated = db.session.execute(
            text('UPDATE "user" SET balance = balance - :amount WHERE id = :user_id AND balance >= :amount'),
            {'user_id': target_user_id, 'amount': amount}
        )
        db.session.commit()

        if updated.rowcount == 0:
            return jsonify({'error': 'Insufficient balance'}), 400

        user = db.session.execute(
            text('SELECT balance FROM "user" WHERE id = :user_id'),
            {'user_id': target_user_id}
        ).fetchone()

        return jsonify({'balance': user[0]}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
