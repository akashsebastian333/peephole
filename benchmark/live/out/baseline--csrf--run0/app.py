from flask import Flask, request

app = Flask(__name__)
accounts = {}

@app.route('/transfer', methods=['POST'])
def transfer():
    from_acc = request.form['from_account']
    to_acc = request.form['to_account']
    amount = float(request.form['amount'])
    accounts[from_acc] = accounts.get(from_acc, 0) - amount
    accounts[to_acc] = accounts.get(to_acc, 0) + amount
    return 'OK'

if __name__ == '__main__':
    app.run()
