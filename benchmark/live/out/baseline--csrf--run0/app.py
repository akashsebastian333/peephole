from flask import Flask, request, jsonify

app = Flask(__name__)

accounts = {'account1': 1000, 'account2': 500}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')

    try:
        amount = float(request.form.get('amount'))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid amount'}), 400

    if not from_account or not to_account:
        return jsonify({'error': 'Missing account fields'}), 400

    if from_account not in accounts or to_account not in accounts:
        return jsonify({'error': 'Account not found'}), 404

    if accounts[from_account] < amount:
        return jsonify({'error': 'Insufficient funds'}), 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return jsonify({
        'success': True,
        'from': from_account,
        'to': to_account,
        'amount': amount
    }), 200

if __name__ == '__main__':
    app.run(debug=True)
