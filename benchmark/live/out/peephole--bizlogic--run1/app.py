from flask import Flask, request, abort
from flask_login import LoginManager, login_required, current_user
from decimal import Decimal

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-me'
app.config['DEBUG'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

login_manager = LoginManager(app)

CATALOG = {'widget_a': Decimal('9.99'), 'widget_b': Decimal('19.99')}
MAX_QTY = 100


@app.route('/order', methods=['POST'])
@login_required
def order():
    product_id = request.form.get('product_id', '')
    try:
        qty = int(request.form.get('qty', ''))
    except ValueError:
        abort(400)
    if qty <= 0 or qty > MAX_QTY:
        abort(400)
    price = CATALOG.get(product_id)
    if price is None:
        abort(404)
    charge_user(current_user.id, qty * price)
    return {'status': 'charged'}


def charge_user(user_id, amount):
    pass
