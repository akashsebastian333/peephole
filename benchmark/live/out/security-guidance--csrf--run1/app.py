from flask import Flask, request, jsonify

app = Flask(__name__)

accounts = {
    "account1": 1000,
    "account2": 500,
    "account3": 1500
}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount_str = request.form.get('amount')

    if not all([from_account, to_account, amount_str]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    if amount <= 0:
        return jsonify({"error": "Amount must be positive"}), 400

    if from_account not in accounts:
        return jsonify({"error": "From account not found"}), 404

    if to_account not in accounts:
        return jsonify({"error": "To account not found"}), 404

    if accounts[from_account] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return jsonify({
        "success": True,
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "from_balance": accounts[from_account],
        "to_balance": accounts[to_account]
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
