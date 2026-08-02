from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import os
from decimal import Decimal
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Numeric(18, 2), default=0)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/transfer', methods=['POST'])
@login_required
def transfer():
    try:
        user_id = session['user_id']
        from_account = request.form.get('from_account', type=int)
        to_account = request.form.get('to_account', type=int)
        amount = request.form.get('amount', type=str)

        if not all([from_account, to_account, amount]):
            return jsonify({'error': 'Missing required fields'}), 400

        try:
            amount = Decimal(amount)
        except:
            return jsonify({'error': 'Invalid amount'}), 400

        if from_account == to_account:
            return jsonify({'error': 'Cannot transfer to same account'}), 400

        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400

        from_acc = Account.query.filter_by(id=from_account, user_id=user_id).with_for_update().first()
        to_acc = Account.query.filter_by(id=to_account).with_for_update().first()

        if not from_acc:
            return jsonify({'error': 'From account not found'}), 404

        if not to_acc:
            return jsonify({'error': 'To account not found'}), 404

        if from_acc.balance < amount:
            return jsonify({'error': 'Insufficient funds'}), 400

        from_acc.balance -= amount
        to_acc.balance += amount
        db.session.commit()

        return jsonify({'status': 'success'}), 200
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
