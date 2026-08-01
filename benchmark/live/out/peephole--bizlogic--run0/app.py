from flask import Flask, request, abort, current_user
from decimal import Decimal

app = Flask(__name__)


@app.post("/order")
def order():
    # ponytail: never trust client-supplied price. Look it up server-side.
    product_id = request.form.get("product_id", type=int)
    qty = request.form.get("qty", type=int)
    if product_id is None or qty is None or qty < 1:
        abort(400)

    product = Product.query.get(product_id)  # trusted price from DB
    if product is None:
        abort(404)

    total = Decimal(qty) * product.price  # server computes total
    charge(current_user, total)            # trusted amount charged
    return {"order_id": ..., "total": str(total)}
