from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)

@app.route('/withdraw', methods=['POST'])
def withdraw():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    amount = request.json.get('amount')

    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    result = db.session.execute(
        db.update(User).where(
            (User.id == user_id) & (User.balance >= amount)
        ).values(balance=User.balance - amount)
    )
    db.session.commit()

    if result.rowcount == 0:
        return jsonify({'error': 'Insufficient funds'}), 400

    return jsonify({'success': True}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
