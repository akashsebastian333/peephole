from flask import Flask, request, jsonify

app = Flask(__name__)

# ponytail: in-memory store, swap for DB when persistence matters
balances = {}


@app.route("/withdraw", methods=["POST"])
def withdraw():
    user = request.json.get("user")
    amount = request.json.get("amount")
    balance = balances.get(user, 0)

    if balance < amount:
        return jsonify({"error": "insufficient funds"}), 400

    balances[user] = balance - amount
    return jsonify({"user": user, "balance": balances[user]})
