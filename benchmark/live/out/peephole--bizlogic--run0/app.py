from flask import Flask, request, session, jsonify
from functools import wraps
import os
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
csrf = CSRFProtect(app)

PRODUCTS = {
    1: {'name': 'Widget A', 'price': 10.00},
    2: {'name': 'Widget B', 'price': 25.00},
}

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/order', methods=['POST'])
@require_auth
@csrf.protect
def order():
    try:
        product_id = int(request.form.get('product_id', 0))
        qty = int(request.form.get('qty', 0))

        if qty <= 0:
            return jsonify({'error': 'Invalid quantity'}), 400

        if product_id not in PRODUCTS:
            return jsonify({'error': 'Product not found'}), 404

        product = PRODUCTS[product_id]
        price = product['price']
        total = qty * price
        user_id = session['user_id']

        success = charge_user(user_id, total)
        if not success:
            return jsonify({'error': 'Charge failed'}), 402

        return jsonify({'total': total, 'status': 'success'})
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input'}), 400

def charge_user(user_id, amount):
    # TODO: Implement payment processing (Stripe, PayPal, etc.)
    return True

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')
