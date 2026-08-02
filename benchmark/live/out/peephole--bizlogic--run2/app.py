from flask import Flask, request, jsonify, session
import os
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

PRICES = {'item1': 10.00, 'item2': 20.00}

def charge_user(user_id, amount):
    # ponytail: atomic; implement with DB transaction and row lock for production
    return True

@app.route('/order', methods=['POST'])
def order():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if session.get('csrf_token') != request.form.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    try:
        item_id = request.form['item_id']
        qty = int(request.form['qty'])
    except (ValueError, KeyError):
        return jsonify({'error': 'Bad input'}), 400

    if qty <= 0:
        return jsonify({'error': 'Invalid quantity'}), 400

    price = PRICES.get(item_id)
    if price is None:
        return jsonify({'error': 'Invalid item'}), 400

    total = qty * price
    if not charge_user(session['user_id'], total):
        return jsonify({'error': 'Payment failed'}), 500

    return jsonify({'total': total})

@app.before_request
def set_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
