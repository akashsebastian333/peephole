import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
db = SQLAlchemy(app)
limiter = Limiter(app=app, key_func=get_remote_address)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=True, nullable=False)
    balance = db.Column(db.Float, nullable=False, default=0.0)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_user_id = request.headers.get('X-User-ID')
        if not auth_user_id:
            return {'error': 'Unauthorized'}, 401
        kwargs['auth_user_id'] = auth_user_id
        return f(*args, **kwargs)
    return decorated_function

@app.route('/withdraw', methods=['POST'])
@limiter.limit("10 per minute")
@require_auth
def withdraw(auth_user_id):
    amount = request.json.get('amount')
    target_user_id = request.json.get('user_id')

    if not amount or amount <= 0 or not target_user_id:
        return {'error': 'Invalid amount or user_id'}, 400

    if str(auth_user_id) != str(target_user_id):
        return {'error': 'Forbidden'}, 403

    try:
        result = db.session.execute(
            text('UPDATE account SET balance = balance - :amount WHERE user_id = :user_id AND balance >= :amount'),
            {'amount': amount, 'user_id': target_user_id}
        )
        db.session.commit()

        if result.rowcount == 0:
            return {'error': 'Insufficient balance or user not found'}, 400

        return {'success': True}, 200
    except Exception as e:
        db.session.rollback()
        return {'error': str(e)}, 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
