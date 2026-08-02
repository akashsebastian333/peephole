from flask import Flask, request, jsonify, session
from functools import wraps
import os
import secrets

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

PRODUCTS = {
    '1': {'id': '1', 'name': 'Widget', 'price': 29.99},
    '2': {'id': '2', 'name': 'Gadget', 'price': 49.99},
}

USERS = {
    '1': {'id': '1', 'email': 'user@example.com', 'balance': 10000},
}

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

@app.before_request
def csrf_protect():
    if request.method == 'POST':
        token = session.get('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            return jsonify({'error': 'CSRF token invalid'}), 403

def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.route('/order', methods=['POST'])
@require_auth
def order():
    user_id = session['user_id']
    user = USERS.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    product_id = request.form.get('product_id')
    qty = request.form.get('qty', type=int)

    if not product_id or qty is None:
        return jsonify({'error': 'Missing product_id or qty'}), 400

    if qty <= 0:
        return jsonify({'error': 'Quantity must be positive'}), 400

    product = PRODUCTS.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    price = product['price']
    total = qty * price

    if user['balance'] < total:
        return jsonify({'error': 'Insufficient funds'}), 402

    user['balance'] -= total

    return jsonify({
        'order_id': 'ORD-001',
        'product_id': product_id,
        'qty': qty,
        'price': price,
        'total': total,
        'user_id': user_id
    }), 201

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1')
