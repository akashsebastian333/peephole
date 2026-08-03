from flask import Flask, request, session
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True

PRODUCT_PRICES = {'product_1': 9.99, 'product_2': 19.99}

@app.route('/order', methods=['POST'])
def order():
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401

    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        return {'error': 'CSRF validation failed'}, 403

    try:
        product_id = request.form['product_id']
        qty = int(request.form['qty'])
    except (KeyError, ValueError):
        return {'error': 'Invalid input'}, 400

    if qty <= 0:
        return {'error': 'Quantity must be positive'}, 400

    if product_id not in PRODUCT_PRICES:
        return {'error': 'Invalid product'}, 400

    price = PRODUCT_PRICES[product_id]
    total = qty * price
    # charge(session['user_id'], total)

    return {'total': total}

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
