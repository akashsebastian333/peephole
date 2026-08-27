from flask import Flask, request

app = Flask(__name__)

accounts = {
    'account1': 1000,
    'account2': 500,
}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_account = request.form.get('from_account')
    to_account = request.form.get('to_account')
    amount = float(request.form.get('amount'))

    if accounts[from_account] >= amount:
        accounts[from_account] -= amount
        accounts[to_account] += amount
        return {'status': 'success'}, 200

    return {'status': 'insufficient funds'}, 400

if __name__ == '__main__':
    app.run(debug=True)
