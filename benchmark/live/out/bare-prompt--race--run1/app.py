from flask import Flask, request, jsonify

app = Flask(__name__)

balances = {}

@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.get_json() or {}
    user_id = data.get('user_id')
    amount = data.get('amount')

    if not user_id or amount is None:
        return jsonify({'error': 'Missing user_id or amount'}), 400

    try:
        amount = float(amount)
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount'}), 400

    if user_id not in balances:
        return jsonify({'error': 'User not found'}), 404

    if balances[user_id] < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    balances[user_id] -= amount
    return jsonify({'balance': balances[user_id]}), 200

if __name__ == '__main__':
    app.run()
