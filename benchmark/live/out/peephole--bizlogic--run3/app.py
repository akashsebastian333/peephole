from flask import Flask, request, session
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os
import stripe

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///orders.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
stripe.api_key = os.environ.get('STRIPE_API_KEY')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    stripe_customer_id = db.Column(db.String, nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.Float, nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    qty = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Float, nullable=False)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return 'Unauthorized', 401
        return f(*args, **kwargs)
    return decorated

@app.route('/order', methods=['POST'])
@login_required
def order():
    user_id = session['user_id']
    product_id = request.form.get('product_id')

    try:
        qty = int(request.form.get('qty', 0))
    except (ValueError, TypeError):
        return 'Invalid qty', 400

    if qty <= 0:
        return 'Qty must be positive', 400

    product = Product.query.get(product_id)
    if not product:
        return 'Product not found', 404

    user = User.query.get(user_id)
    if not user:
        return 'User not found', 404

    total = qty * product.price

    try:
        stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            customer=user.stripe_customer_id
        )
    except stripe.error.CardError:
        return 'Charge failed', 400

    order_obj = Order(user_id=user_id, product_id=product_id, qty=qty, total=total)
    db.session.add(order_obj)
    db.session.commit()

    return 'Order created', 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
