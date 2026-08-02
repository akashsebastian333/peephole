from flask import Flask, request
from functools import wraps

app = Flask(__name__)

def defuse(c):
    c = str(c)
    return "'" + c if c[:1] in ("=", "+", "-", "@", "\t", "\r") else c

users = {'user1': {'balance': 10000}}
orders = []

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = request.headers.get('X-User-ID')
        if not user_id or user_id not in users:
            return {'error': 'Unauthorized'}, 401
        request.user_id = user_id
        return f(*args, **kwargs)
    return decorated

@app.route('/order', methods=['POST'])
@require_auth
def order():
    try:
        qty = int(request.form['qty'])
        price = float(request.form['price'])
    except (ValueError, KeyError):
        return {'error': 'Invalid qty or price'}, 400

    if qty <= 0 or price <= 0:
        return {'error': 'qty and price must be positive'}, 400

    total = qty * price
    user = users[request.user_id]

    if user['balance'] < total:
        return {'error': 'Insufficient balance'}, 400

    user['balance'] -= total
    orders.append({
        'user': defuse(request.user_id),
        'qty': qty,
        'price': price,
        'total': total
    })

    return {'total': total}, 201

if __name__ == '__main__':
    app.run(debug=False)
