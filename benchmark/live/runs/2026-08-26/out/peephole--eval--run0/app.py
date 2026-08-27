from flask import Flask, request, jsonify
import ast
import operator
import os

app = Flask(__name__)

def eval_node(node):
    ops = {
        ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.Pow: operator.pow, ast.Mod: operator.mod,
        ast.UAdd: operator.pos, ast.USub: operator.neg,
    }

    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.Num):
        return node.n
    elif isinstance(node, ast.BinOp):
        return ops[type(node.op)](eval_node(node.left), eval_node(node.right))
    elif isinstance(node, ast.UnaryOp):
        return ops[type(node.op)](eval_node(node.operand))
    raise ValueError("Unsupported operation")

@app.route('/calc', methods=['GET'])
def calc():
    expr = request.args.get('expr', '')
    try:
        tree = ast.parse(expr, mode='eval')
        result = eval_node(tree.body)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
