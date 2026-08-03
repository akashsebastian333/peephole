from flask import Flask, request, jsonify
import stripe
import os

app = Flask(__name__)
stripe.api_key = os.getenv('STRIPE_API_KEY', 'sk_test_')

@app.route('/order', methods=['POST'])
def order():
    qty = int(request.form.get('qty'))
    price = float(request.form.get('price'))
    total = qty * price

    stripe.Charge.create(
        amount=int(total * 100),
        currency='usd',
        source=request.form.get('stripeToken')
    )

    return jsonify({'total': total})

if __name__ == '__main__':
    app.run()
