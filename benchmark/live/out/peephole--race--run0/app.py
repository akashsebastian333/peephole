import os
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['WTF_CSRF_SSL_STRICT'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0.0)

@app.route('/withdraw', methods=['POST'])
@csrf.protect
def withdraw():
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = request.json.get('user_id')
    amount = request.json.get('amount')

    if current_user_id != user_id:
        return jsonify({'error': 'Forbidden'}), 403

    if not isinstance(amount, (int, float)) or amount <= 0:
        return jsonify({'error': 'Amount must be a positive number'}), 400

    result = db.session.execute(
        text('UPDATE users SET balance = balance - :amount WHERE id = :user_id AND balance >= :amount'),
        {'user_id': user_id, 'amount': amount}
    )
    db.session.commit()

    if result.rowcount == 0:
        return jsonify({'error': 'Insufficient balance'}), 400

    user = db.session.execute(
        text('SELECT balance FROM users WHERE id = :user_id'),
        {'user_id': user_id}
    ).fetchone()

    return jsonify({'new_balance': user[0]}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
