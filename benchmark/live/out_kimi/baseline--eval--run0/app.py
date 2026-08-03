from flask import Flask, request

app = Flask(__name__)


@app.route('/calc')
def calc():
    return str(eval(request.args['expr']))


if __name__ == '__main__':
    # ponytail: binds 127.0.0.1 by default — do not add host='0.0.0.0'
    app.run()
