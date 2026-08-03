from flask import Flask, request, jsonify, session
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
csrf = CSRFProtect(app)

PRODUCT_PRICES = {'1': 100.0, '2': 250.0, '3': 50.0}

@app.route('/order', methods=['POST'])
def order():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']

    try:
        qty = int(request.form.get('qty', 0))
        product_id = request.form.get('product_id', '')
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input'}), 400

    if qty <= 0:
        return jsonify({'error': 'Qty must be positive'}), 400

    if product_id not in PRODUCT_PRICES:
        return jsonify({'error': 'Invalid product'}), 400

    price = PRODUCT_PRICES[product_id]
    total = qty * price
    # charge_user(user_id, total)

    return jsonify({'total': total, 'status': 'success'}), 200

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
