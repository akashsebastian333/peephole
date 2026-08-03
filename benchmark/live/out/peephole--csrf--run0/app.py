from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import os
from decimal import Decimal
from sqlalchemy import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///bank.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG') == '1'
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_number = db.Column(db.String(50), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    balance = db.Column(db.Numeric(12, 2), nullable=False)

@app.route('/transfer', methods=['POST'])
def transfer():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    from_acc_num = request.form.get('from_account')
    to_acc_num = request.form.get('to_account')
    amount_str = request.form.get('amount')

    if not all([from_acc_num, to_acc_num, amount_str]):
        return jsonify({'error': 'Missing fields'}), 400

    try:
        amount = Decimal(amount_str)
    except:
        return jsonify({'error': 'Invalid amount'}), 400

    if amount <= 0:
        return jsonify({'error': 'Amount must be positive'}), 400

    try:
        from_acc = Account.query.filter_by(account_number=from_acc_num, owner_id=user_id).with_for_update().first()
        if not from_acc:
            return jsonify({'error': 'From account not found or unauthorized'}), 404

        to_acc = Account.query.filter_by(account_number=to_acc_num).with_for_update().first()
        if not to_acc:
            return jsonify({'error': 'To account not found'}), 404

        result = db.session.execute(
            text("""
            UPDATE accounts
            SET balance = balance - :amount
            WHERE id = :id AND balance >= :amount
            """),
            {"amount": amount, "id": from_acc.id}
        )

        if result.rowcount == 0:
            db.session.rollback()
            return jsonify({'error': 'Insufficient balance'}), 400

        db.session.execute(
            text("""
            UPDATE accounts
            SET balance = balance + :amount
            WHERE id = :id
            """),
            {"amount": amount, "id": to_acc.id}
        )

        db.session.commit()
        return jsonify({'message': 'Transfer successful'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
