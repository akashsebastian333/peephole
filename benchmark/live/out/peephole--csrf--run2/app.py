from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    balance = db.Column(db.Float, nullable=False)

@auth.verify_password
def verify_password(username, password):
    user = Account.query.filter_by(username=username).first()
    return user.username if user else None

@app.route('/transfer', methods=['POST'])
@auth.login_required
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount = request.form.get('amount')

    if not all([from_account, to_account, amount]):
        return jsonify({'error': 'Missing fields'}), 400

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    if auth.current_user() != from_account:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        from_acc = Account.query.filter_by(username=from_account).with_for_update().first()
        if not from_acc:
            return jsonify({'error': 'Account not found'}), 404

        to_acc = Account.query.filter_by(username=to_account).with_for_update().first()
        if not to_acc:
            return jsonify({'error': 'Recipient not found'}), 404

        if from_acc.balance < amount:
            return jsonify({'error': 'Insufficient balance'}), 400

        from_acc.balance -= amount
        to_acc.balance += amount
        db.session.commit()

        return jsonify({'success': True, 'new_balance': from_acc.balance}), 200
    except Exception:
        db.session.rollback()
        return jsonify({'error': 'Transfer failed'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
