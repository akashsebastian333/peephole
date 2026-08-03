from flask import Flask, request, jsonify

app = Flask(__name__)

accounts = {
    "account1": 1000,
    "account2": 500
}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account', '').strip()
    to_account = request.form.get('to_account', '').strip()
    amount_str = request.form.get('amount', '').strip()

    if not from_account or not to_account:
        return jsonify({"error": "from_account and to_account required"}), 400

    if from_account == to_account:
        return jsonify({"error": "Cannot transfer to same account"}), 400

    try:
        amount = float(amount_str)
        if amount <= 0:
            return jsonify({"error": "Amount must be positive"}), 400
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid amount"}), 400

    if from_account not in accounts or to_account not in accounts:
        return jsonify({"error": "Account not found"}), 404

    if accounts[from_account] < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return jsonify({"success": True}), 200

if __name__ == '__main__':
    app.run(debug=True)
