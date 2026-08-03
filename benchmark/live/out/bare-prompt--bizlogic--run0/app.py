from flask import Flask, request, jsonify
import stripe
import os

app = Flask(__name__)
stripe.api_key = os.environ.get('STRIPE_API_KEY')

@app.route('/order', methods=['POST'])
def order():
    try:
        qty = float(request.form.get('qty'))
        price = float(request.form.get('price'))

        if qty <= 0 or price <= 0:
            return jsonify({'error': 'qty and price must be positive'}), 400

        total = qty * price

        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            source=request.form.get('stripe_token'),
            description=f'Order: {qty} items at ${price} each'
        )

        return jsonify({'total': total, 'charge_id': charge.id})
    except ValueError:
        return jsonify({'error': 'Invalid qty or price'}), 400
    except stripe.error.CardError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=False)
