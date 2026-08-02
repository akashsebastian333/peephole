from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    # WARNING: eval() executes arbitrary code - only use in trusted/sandboxed environments
    result = eval(expr)
    return {'result': result}

if __name__ == '__main__':
    app.run()
