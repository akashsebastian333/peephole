from flask import Flask, request, jsonify

app = Flask(__name__)

accounts = {
    'account1': 1000.0,
    'account2': 500.0,
}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount = float(request.form.get('amount'))

    if from_account not in accounts or to_account not in accounts:
        return {'error': 'Invalid account'}, 400

    if accounts[from_account] < amount:
        return {'error': 'Insufficient funds'}, 400

    accounts[from_account] -= amount
    accounts[to_account] += amount

    return {'success': True, 'from_balance': accounts[from_account], 'to_balance': accounts[to_account]}, 200

if __name__ == '__main__':
    app.run(debug=True)
