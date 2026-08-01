from flask import Flask, request, jsonify

app = Flask(__name__)
balances = {}


@app.route("/withdraw", methods=["POST"])
def withdraw():
    user_id = request.json.get("user_id")
    amount = request.json.get("amount")

    balance = balances.get(user_id, 0)
    if balance < amount:
        return jsonify({"error": "insufficient funds"}), 400

    balances[user_id] = balance - amount
    return jsonify({"balance": balances[user_id]})


if __name__ == "__main__":
    app.run()
