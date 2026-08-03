import os
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///bank.db')
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG') == '1'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    balance = db.Column(db.Float, nullable=False, default=0.0)

@app.route('/transfer', methods=['POST'])
@csrf.protect
def transfer():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount = request.form.get('amount')

    if not from_account or not to_account or not amount:
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        amount = float(amount)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    try:
        from_id = int(from_account)
        to_id = int(to_account)
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid account ID'}), 400

    if from_id == to_id:
        return jsonify({'error': 'Cannot transfer to same account'}), 400

    try:
        db.session.begin()

        src = db.session.query(Account).filter(Account.id == from_id).with_for_update().first()
        dst = db.session.query(Account).filter(Account.id == to_id).with_for_update().first()

        if not src or not dst:
            db.session.rollback()
            return jsonify({'error': 'Account not found'}), 404

        if src.user_id != user_id:
            db.session.rollback()
            return jsonify({'error': 'Forbidden'}), 403

        if src.balance < amount:
            db.session.rollback()
            return jsonify({'error': 'Insufficient balance'}), 400

        src.balance -= amount
        dst.balance += amount

        db.session.commit()
        return jsonify({'success': True, 'from_balance': src.balance, 'to_balance': dst.balance}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    app.run()
