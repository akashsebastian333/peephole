from flask import Flask, request, jsonify

app = Flask(__name__)

balances = {}

@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.json
    user_id = data.get('user_id')
    amount = data.get('amount')

    if user_id not in balances:
        return jsonify({'error': 'User not found'}), 404

    if balances[user_id] < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    balances[user_id] -= amount
    return jsonify({'balance': balances[user_id]}), 200

if __name__ == '__main__':
    app.run(debug=True)
