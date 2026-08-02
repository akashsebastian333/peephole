import os
from functools import wraps
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import update, and_
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
db = SQLAlchemy(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    balance = db.Column(db.Float, default=0.0, nullable=False)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return {'error': 'Unauthorized'}, 401
        return f(*args, **kwargs)
    return decorated_function

def csrf_token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-CSRF-Token') or request.get_json().get('csrf_token')
        if token != session.get('csrf_token'):
            return {'error': 'CSRF token invalid'}, 403
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def set_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return {'error': 'Missing credentials'}, 400

    user = db.session.execute(db.select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not check_password_hash(user.password, password):
        return {'error': 'Invalid credentials'}, 401

    session['user_id'] = user.id
    return {'csrf_token': session['csrf_token']}, 200

@app.route('/withdraw', methods=['POST'])
@login_required
@csrf_token_required
@limiter.limit("10 per minute")
def withdraw():
    authenticated_user_id = session['user_id']
    data = request.get_json()
    amount = data.get('amount')

    if amount is None or amount <= 0:
        return {'error': 'Invalid amount'}, 400

    # Atomic update scoped to authenticated user - prevents IDOR and TOCTOU
    stmt = update(User).where(
        and_(User.id == authenticated_user_id, User.balance >= amount)
    ).values(balance=User.balance - amount)

    result = db.session.execute(stmt)
    db.session.commit()

    if result.rowcount == 0:
        return {'error': 'Insufficient balance'}, 400

    user = db.session.get(User, authenticated_user_id)
    return {'balance': user.balance}, 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
