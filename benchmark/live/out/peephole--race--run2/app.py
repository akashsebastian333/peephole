from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0)

@app.route('/withdraw', methods=['POST'])
@csrf.protect
def withdraw():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    amount = data.get('amount')

    if not amount or amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    with db.session.begin():
        user = db.session.execute(
            db.select(User).where(User.id == user_id).with_for_update()
        ).scalar_one_or_none()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if user.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        user.balance -= amount

    return jsonify({'balance': user.balance}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()
