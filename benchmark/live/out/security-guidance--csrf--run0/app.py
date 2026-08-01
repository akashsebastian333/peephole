from flask import Flask, request

app = Flask(__name__)
accounts = {"alice": 100, "bob": 100}


@app.post("/transfer")
def transfer():
    from_acc = request.form["from_account"]
    to_acc = request.form["to_account"]
    amount = float(request.form["amount"])
    accounts[from_acc] -= amount
    accounts[to_acc] += amount
    return {"ok": True, "accounts": accounts}


if __name__ == "__main__":
    app.run()
