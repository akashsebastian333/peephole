from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    return str(eval(expr))

if __name__ == '__main__':
    app.run()
