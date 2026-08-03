import os
from flask import Flask, request, jsonify
import stripe

app = Flask(__name__)
stripe.api_key = os.getenv('STRIPE_API_KEY')

@app.route('/order', methods=['POST'])
def order():
    try:
        qty = int(request.form['qty'])
        price = float(request.form['price'])
        token = request.form['stripeToken']

        if qty <= 0 or price < 0:
            return jsonify({'error': 'Invalid qty or price'}), 400

        total = qty * price

        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            source=token
        )

        return jsonify({
            'total': total,
            'chargeId': charge.id
        })
    except (ValueError, KeyError):
        return jsonify({'error': 'Invalid input'}), 400
    except stripe.error.StripeError:
        return jsonify({'error': 'Payment failed'}), 400

if __name__ == '__main__':
    app.run(debug=True)
