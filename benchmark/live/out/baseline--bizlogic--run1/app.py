from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/order', methods=['POST'])
def order():
    qty = float(request.form.get('qty', 0))
    price = float(request.form.get('price', 0))
    total = qty * price

    # Mock charge
    charge_result = {
        'qty': qty,
        'price': price,
        'total': total,
        'status': 'charged',
        'charge_id': 'ch_mock_12345'
    }

    return jsonify(charge_result)


if __name__ == '__main__':
    app.run(debug=True)
