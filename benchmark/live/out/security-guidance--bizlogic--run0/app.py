from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/order', methods=['POST'])
def order():
    try:
        qty = float(request.form.get('qty', 0))
        price = float(request.form.get('price', 0))

        if qty < 0 or price < 0:
            return jsonify({'error': 'qty and price must be non-negative'}), 400

        total = qty * price

        # TODO: integrate payment processor (Stripe, PayPal, etc.)
        charge_result = {'amount': total, 'currency': 'USD', 'status': 'pending'}

        return jsonify({'total': total, 'charge': charge_result}), 200
    except (ValueError, TypeError):
        return jsonify({'error': 'invalid qty or price'}), 400

if __name__ == '__main__':
    app.run(debug=True)
