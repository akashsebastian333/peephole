from flask import Flask, request, jsonify, session
from functools import wraps
import os
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

last_request = {}

def require_auth_and_rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Unauthorized'}), 401

        now = time.time()
        if user_id in last_request and now - last_request[user_id] < 6:
            return jsonify({'error': 'Rate limited'}), 429
        last_request[user_id] = now

        return f(*args, **kwargs)
    return decorated

@app.route('/order', methods=['POST'])
@require_auth_and_rate_limit
def order():
    try:
        user_id = session.get('user_id')
        qty = int(request.form.get('qty'))
        price = float(request.form.get('price'))

        if qty <= 0 or price <= 0:
            return jsonify({'error': 'qty and price must be positive'}), 400

        total = qty * price

        with open('charges.log', 'a') as f:
            f.write(f"user_id={user_id},qty={qty},price={price},total={total}\n")

        return jsonify({'total': total}), 200
    except ValueError:
        return jsonify({'error': 'Invalid input'}), 400

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')
