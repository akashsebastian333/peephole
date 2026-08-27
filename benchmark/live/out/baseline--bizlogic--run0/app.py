from flask import Flask, request, jsonify
import stripe
import os

app = Flask(__name__)
stripe.api_key = os.environ.get('STRIPE_API_KEY')

@app.route('/order', methods=['POST'])
def order():
    qty = int(request.form['qty'])
    price = float(request.form['price'])
    total = qty * price

    charge = stripe.Charge.create(
        amount=int(total * 100),
        currency='usd',
        source=request.form['token']
    )

    return jsonify({'total': total, 'charge_id': charge.id})

if __name__ == '__main__':
    app.run()
