from flask import Flask, request
import ast, operator, os

app = Flask(__name__)

def safe_eval(expr):
    ops = {
        ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.Pow: operator.pow,
    }
    def eval_node(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Num):
            return node.n
        if isinstance(node, ast.BinOp):
            return ops[type(node.op)](eval_node(node.left), eval_node(node.right))
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -eval_node(node.operand)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
            return eval_node(node.operand)
        raise ValueError("Invalid operation")
    return eval_node(ast.parse(expr, mode='eval').body)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        return {'result': safe_eval(expr)}
    except:
        return {'error': 'Invalid expression'}, 400

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
