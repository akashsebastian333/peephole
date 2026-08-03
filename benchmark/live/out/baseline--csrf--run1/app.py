from flask import Flask, request, jsonify

app = Flask(__name__)

accounts = {
    "account1": 1000.0,
    "account2": 500.0,
}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount_str = request.form.get('amount')

    try:
        amount = float(amount_str)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    if from_account not in accounts or to_account not in accounts:
        return jsonify({"error": "Account not found"}), 404

    if accounts[from_account] < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return jsonify({
        "success": True,
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount
    })

if __name__ == '__main__':
    app.run(debug=True)
