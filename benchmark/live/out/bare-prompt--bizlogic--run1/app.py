from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/order', methods=['POST'])
def order():
    try:
        qty_str = request.form.get('qty')
        price_str = request.form.get('price')

        if not qty_str or not price_str:
            return jsonify({'error': 'qty and price required'}), 400

        qty = float(qty_str)
        price = float(price_str)

        if qty < 0 or price < 0:
            return jsonify({'error': 'qty and price must be non-negative'}), 400

        total = qty * price
        # charge_user(user_id, total)

        return jsonify({'total': total}), 200
    except ValueError:
        return jsonify({'error': 'qty and price must be valid numbers'}), 400

if __name__ == '__main__':
    app.run(debug=False)
