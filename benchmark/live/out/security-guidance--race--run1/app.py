from flask import Flask, request, jsonify

app = Flask(__name__)

users = {"user1": {"balance": 1000}}

@app.route('/withdraw', methods=['POST'])
def withdraw():
    data = request.json or {}
    user_id = data.get('user_id')
    amount = data.get('amount')

    if not user_id or amount is None:
        return jsonify({"error": "Missing user_id or amount"}), 400

    if user_id not in users:
        return jsonify({"error": "User not found"}), 404

    if users[user_id]["balance"] < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    users[user_id]["balance"] -= amount
    return jsonify({"balance": users[user_id]["balance"]})

if __name__ == '__main__':
    app.run()
