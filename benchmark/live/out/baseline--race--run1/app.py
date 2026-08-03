from flask import Flask, request, jsonify

app = Flask(__name__)
balances = {}


@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.get_json()
    user_id = data.get('user_id')
    amount = data.get('amount')

    if user_id not in balances:
        balances[user_id] = 0

    if balances[user_id] >= amount:
        balances[user_id] -= amount
        return jsonify({'success': True, 'new_balance': balances[user_id]}), 200
    else:
        return jsonify({'success': False, 'error': 'Insufficient balance'}), 400


if __name__ == '__main__':
    app.run(debug=True)
