from flask import Flask, request, jsonify

app = Flask(__name__)

balances = {}

@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.get_json()
    user_id = data.get('user_id')
    amount = data.get('amount')

    if user_id not in balances:
        return jsonify({'error': 'User not found'}), 404

    if balances[user_id] >= amount:
        balances[user_id] -= amount
        return jsonify({'balance': balances[user_id]})

    return jsonify({'error': 'Insufficient balance'}), 400

if __name__ == '__main__':
    app.run()
