from flask import Flask, request, jsonify
import stripe

app = Flask(__name__)
stripe.api_key = "sk_test_..."

@app.route('/order', methods=['POST'])
def order():
    try:
        qty = int(request.form['qty'])
        price = float(request.form['price'])

        if qty <= 0 or price <= 0:
            return jsonify({'error': 'invalid qty or price'}), 400

        total = qty * price

        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            source=request.form['token']
        )

        return jsonify({'status': 'success', 'total': total, 'charge_id': charge.id})
    except (KeyError, ValueError):
        return jsonify({'error': 'missing or invalid fields'}), 400
    except stripe.error.CardError as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
