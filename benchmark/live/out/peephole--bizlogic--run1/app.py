from flask import Flask, request, jsonify
from decimal import Decimal
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'
csrf = CSRFProtect(app)

PRODUCTS = {
    "widget": Decimal("19.99"),
    "gadget": Decimal("29.99")
}

@app.route("/order", methods=["POST"])
@csrf.protect
def order():
    try:
        product_id = request.form["product_id"]
        qty = Decimal(request.form["qty"])

        if qty <= 0 or qty > 1000000:
            return jsonify({"error": "invalid quantity"}), 400

        if product_id not in PRODUCTS:
            return jsonify({"error": "product not found"}), 404

        price = PRODUCTS[product_id]
        total = qty * price
        charge_user(total)

        return jsonify({"total": str(total)}), 200
    except (ValueError, KeyError):
        return jsonify({"error": "invalid input"}), 400

def charge_user(amount):
    pass

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
