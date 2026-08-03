import os
from flask import Flask, request, jsonify
import stripe

app = Flask(__name__)
stripe.api_key = os.getenv('STRIPE_API_KEY')

@app.route('/order', methods=['POST'])
def order():
    qty = request.form.get('qty', type=int)
    price = request.form.get('price', type=float)
    token = request.form.get('token')

    if not all([qty, price, token]):
        return jsonify({'error': 'Missing qty, price, or token'}), 400

    total = qty * price

    try:
        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            source=token
        )
        return jsonify({'success': True, 'total': total, 'charge_id': charge.id})
    except stripe.error.StripeError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
