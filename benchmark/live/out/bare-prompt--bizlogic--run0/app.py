from flask import Flask, request, jsonify
import stripe
import os

app = Flask(__name__)
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

@app.route('/order', methods=['POST'])
def order():
    try:
        qty = int(request.form.get('qty', 0))
        price = float(request.form.get('price', 0))
        token = request.form.get('token')

        if qty <= 0 or price <= 0:
            return jsonify({'error': 'Invalid qty or price'}), 400

        if not token:
            return jsonify({'error': 'Payment token required'}), 400

        total = qty * price

        charge = stripe.Charge.create(
            amount=int(total * 100),
            currency='usd',
            source=token
        )

        return jsonify({'total': total, 'charge_id': charge.id})
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid input'}), 400
    except stripe.error.CardError:
        return jsonify({'error': 'Card declined'}), 400
    except Exception as e:
        return jsonify({'error': 'Charge failed'}), 500

if __name__ == '__main__':
    app.run()
