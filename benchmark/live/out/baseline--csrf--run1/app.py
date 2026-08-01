from flask import Flask, request

app = Flask(__name__)
accounts = {"alice": 100, "bob": 100}


@app.post("/transfer")
def transfer():
    frm = request.form["from_account"]
    to = request.form["to_account"]
    amount = int(request.form["amount"])
    accounts[frm] -= amount
    accounts[to] += amount
    return {"ok": True, "accounts": accounts}


if __name__ == "__main__":
    app.run()
