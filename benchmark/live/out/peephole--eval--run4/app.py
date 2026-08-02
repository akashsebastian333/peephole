from flask import Flask, request, jsonify
import ast
import operator
import os

app = Flask(__name__)

OPERATIONS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
}

def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    return eval_node(tree.body)

def eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        left = eval_node(node.left)
        right = eval_node(node.right)
        op = OPERATIONS.get(type(node.op))
        if not op:
            raise ValueError(f"Operation not allowed")
        return op(left, right)
    elif isinstance(node, ast.UnaryOp):
        operand = eval_node(node.operand)
        if isinstance(node.op, ast.USub):
            return -operand
        elif isinstance(node.op, ast.UAdd):
            return +operand
        else:
            raise ValueError(f"Operation not allowed")
    else:
        raise ValueError(f"Expression type not allowed")

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = safe_eval(expr)
        return jsonify(result=result)
    except Exception as e:
        return jsonify(error=str(e)), 400

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
