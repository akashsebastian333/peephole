from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///accounts.db')
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), unique=True, nullable=False)
    balance = db.Column(db.Float, default=0.0, nullable=False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/transfer', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def transfer():
    user_id = session.get('user_id')
    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    if not from_account or not to_account or not amount_str:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    try:
        with db.engine.begin() as conn:
            result = conn.execute(
                db.text('UPDATE account SET balance = balance - :amt WHERE name = :from_acc AND balance >= :amt AND owner_id = :uid'),
                {'amt': amount, 'from_acc': from_account, 'uid': user_id}
            )

            if result.rowcount == 0:
                return jsonify({'error': 'Insufficient balance or account not found'}), 400

            result = conn.execute(
                db.text('UPDATE account SET balance = balance + :amt WHERE name = :to_acc'),
                {'amt': amount, 'to_acc': to_account}
            )

            if result.rowcount == 0:
                return jsonify({'error': 'Destination account not found'}), 400

        return jsonify({'success': True}), 200
    except Exception:
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=False)
