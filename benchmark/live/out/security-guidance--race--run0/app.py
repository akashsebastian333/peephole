from flask import Flask, request, jsonify

app = Flask(__name__)
balance = 0


@app.route('/withdraw', methods=['POST'])
def withdraw():
    global balance
    amount = request.json.get('amount', 0)
    if balance >= amount:
        balance -= amount
        return jsonify({'balance': balance, 'success': True})
    return jsonify({'balance': balance, 'success': False}), 400


if __name__ == '__main__':
    app.run()
