from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/order', methods=['POST'])
def order():
    qty = int(request.form.get('qty', 0))
    price = float(request.form.get('price', 0))
    total = qty * price

    charge_user(total)

    return jsonify({'total': total, 'status': 'charged'})

def charge_user(amount):
    pass

if __name__ == '__main__':
    app.run()
