from flask import Flask, request

app = Flask(__name__)

accounts = {}


@app.route("/transfer", methods=["POST"])
def transfer():
    from_account = request.form["from_account"]
    to_account = request.form["to_account"]
    amount = float(request.form["amount"])

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return "ok"
