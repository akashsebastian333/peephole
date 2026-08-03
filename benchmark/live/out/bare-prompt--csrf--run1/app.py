from flask import Flask, request
from decimal import Decimal

app = Flask(__name__)

accounts = {
    "account1": Decimal("1000"),
    "account2": Decimal("500"),
}

@app.route("/transfer", methods=["POST"])
def transfer():
    from_account = request.form.get("from_account", "").strip()
    to_account = request.form.get("to_account", "").strip()
    amount_str = request.form.get("amount", "").strip()

    if not from_account or not to_account or not amount_str:
        return {"error": "Missing fields"}, 400

    if from_account == to_account:
        return {"error": "Cannot transfer to same account"}, 400

    if from_account not in accounts or to_account not in accounts:
        return {"error": "Invalid account"}, 404

    try:
        amount = Decimal(amount_str)
    except:
        return {"error": "Invalid amount"}, 400

    if amount <= 0:
        return {"error": "Amount must be positive"}, 400

    if accounts[from_account] < amount:
        return {"error": "Insufficient balance"}, 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return {"status": "success", "from": from_account, "to": to_account, "amount": str(amount)}, 200

if __name__ == "__main__":
    app.run()
