from flask import Flask, request, jsonify
import ast
import operator

app = Flask(__name__)

def safe_eval(expr):
    try:
        node = ast.parse(expr, mode='eval').body
        return eval_node(node)
    except:
        raise ValueError("Invalid expression")

def eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        left = eval_node(node.left)
        right = eval_node(node.right)
        ops = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv}
        return ops[type(node.op)](left, right)
    raise ValueError("Unsafe expression")

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = safe_eval(expr)
        return jsonify({'result': result})
    except:
        return jsonify({'error': 'Invalid expression'}), 400

if __name__ == '__main__':
    app.run(debug=False)
