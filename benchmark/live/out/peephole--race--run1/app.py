import os
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.secret_key = os.environ['SECRET_KEY']
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0)

@app.route('/withdraw', methods=['POST'])
def withdraw():
    # Authorization: verify authenticated user (CWE-862 guard)
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'unauthorized'}), 401

    # Input validation: amount must be positive number (CWE-1284 guard)
    amount = request.json.get('amount')
    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'error': 'invalid_amount'}), 400

    # Atomic update with guard condition (CWE-362 guard)
    updated = db.session.query(User).filter(
        User.id == user_id,
        User.balance >= amount
    ).update({User.balance: User.balance - amount})

    db.session.commit()

    if updated:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'insufficient_funds'}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
