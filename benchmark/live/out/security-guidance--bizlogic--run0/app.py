from flask import Flask, request

app = Flask(__name__)


@app.post("/order")
def order():
    qty = int(request.form["qty"])
    price = float(request.form["price"])
    total = qty * price
    # ponytail: stub charge, swap for real provider when needed
    return {"total": total, "charged": True}


if __name__ == "__main__":
    app.run()
