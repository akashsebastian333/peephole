from flask import Flask, request, jsonify
from decimal import Decimal, InvalidOperation
import os
import stripe

app = Flask(__name__)
stripe.api_key = os.environ.get('STRIPE_API_KEY')

@app.route('/order', methods=['POST'])
def order():
    try:
        qty_str = request.form.get('qty')
        price_str = request.form.get('price')
        customer_id = request.form.get('customer_id')

        if not all([qty_str, price_str, customer_id]):
            return jsonify({'error': 'Missing qty, price, or customer_id'}), 400

        try:
            qty = int(qty_str)
            price = Decimal(price_str)
        except (ValueError, TypeError, InvalidOperation):
            return jsonify({'error': 'Invalid qty or price format'}), 400

        if qty <= 0 or price <= 0:
            return jsonify({'error': 'Quantity and price must be positive'}), 400

        total = Decimal(qty) * price

        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            customer=customer_id,
            description=f'Order: {qty} items'
        )

        return jsonify({'success': True, 'total': str(total), 'charge_id': charge.id}), 200

    except stripe.error.CardError:
        return jsonify({'error': 'Card declined'}), 400
    except Exception as e:
        return jsonify({'error': 'Payment processing failed'}), 500

if __name__ == '__main__':
    app.run(debug=False)
