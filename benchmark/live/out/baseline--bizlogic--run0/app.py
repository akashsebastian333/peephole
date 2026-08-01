from flask import Flask, request

app = Flask(__name__)


@app.route('/order', methods=['POST'])
def order():
    total = int(request.form['qty']) * float(request.form['price'])
    charge(total)
    return {'total': total}


def charge(amount):
    pass
