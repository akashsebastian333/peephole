from flask import Flask, request

app = Flask(__name__)


@app.route("/order", methods=["POST"])
def order():
    qty = int(request.form["qty"])
    price = float(request.form["price"])
    total = qty * price
    return {"total": total, "charged": True}
