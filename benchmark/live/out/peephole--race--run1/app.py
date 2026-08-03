from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    balance = db.Column(db.Float, default=0)

@app.route('/withdraw', methods=['POST'])
def withdraw():
    user_id = int(request.headers.get('X-User-ID', 0))
    amount = float(request.json.get('amount', 0))

    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    with db.session.begin():
        updated = db.session.query(User).filter(
            User.id == user_id,
            User.balance >= amount
        ).update({User.balance: User.balance - amount})

    if not updated:
        return jsonify({'error': 'Insufficient balance'}), 400

    return jsonify({'success': True})

if __name__ == '__main__':
    db.create_all()
    app.run()
