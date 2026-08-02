import ast
import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/calc')
def calc():
    try:
        expr = request.args.get('expr', '')
        result = ast.literal_eval(expr)
        return str(result)
    except Exception as e:
        return str(e), 400

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')
