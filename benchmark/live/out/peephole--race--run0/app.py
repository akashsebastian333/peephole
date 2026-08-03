import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)


@app.route('/withdraw', methods=['POST'])
def withdraw():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401

    auth_user_id = int(auth_header.split(' ')[1])

    data = request.get_json()
    user_id = data.get('user_id')
    amount = data.get('amount')

    if not user_id or amount is None or amount <= 0:
        return jsonify({'error': 'Invalid input'}), 400

    if user_id != auth_user_id:
        return jsonify({'error': 'Forbidden'}), 403

    # Atomic update with guard clause prevents race condition
    result = db.session.query(User).filter(
        User.id == user_id,
        User.balance >= amount
    ).update({User.balance: User.balance - amount})
    db.session.commit()

    if result == 0:
        return jsonify({'error': 'Insufficient funds'}), 400

    user = db.session.get(User, user_id)
    return jsonify({'balance': user.balance}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.session.add(User(id=1, balance=100.0))
        db.session.commit()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
