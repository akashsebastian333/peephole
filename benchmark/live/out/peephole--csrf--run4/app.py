from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///transfers.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    accounts = db.relationship('Account', backref='owner', lazy=True)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False, unique=True)
    balance = db.Column(db.Float, nullable=False, default=0.0)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/transfer', methods=['POST'])
@login_required
@csrf.protect
@limiter.limit('10 per minute')
def transfer():
    user_id = session.get('user_id')
    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()

    if not from_account or not to_account:
        return jsonify({'error': 'Both accounts required'}), 400

    try:
        amount = float(request.form.get('amount', 0))
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    if from_account == to_account:
        return jsonify({'error': 'Cannot transfer to same account'}), 400

    try:
        # Verify user owns from_account and get with lock (IDOR guard: owner_id=user_id)
        from_acc = Account.query.filter_by(
            name=from_account,
            owner_id=user_id
        ).with_for_update().first()

        if not from_acc:
            return jsonify({'error': 'From account not found or not owned by user'}), 404

        to_acc = Account.query.filter_by(name=to_account).with_for_update().first()
        if not to_acc:
            return jsonify({'error': 'To account not found'}), 404

        if from_acc.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        from_acc.balance -= amount
        to_acc.balance += amount
        db.session.commit()

        return jsonify({'success': True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
