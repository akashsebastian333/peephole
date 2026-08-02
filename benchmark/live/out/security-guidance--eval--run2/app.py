from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        # eval() explicitly requested; security risk — use only in controlled contexts
        result = eval(expr)
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

if __name__ == '__main__':
    app.run()
