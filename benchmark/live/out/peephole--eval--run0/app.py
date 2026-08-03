from flask import Flask, request
import ast
import operator

app = Flask(__name__)

def safe_eval(expr):
    node = ast.parse(expr, mode='eval').body
    return eval_node(node)

def eval_node(node):
    if isinstance(node, ast.Constant):
        return node.value
    elif isinstance(node, ast.BinOp):
        left = eval_node(node.left)
        right = eval_node(node.right)
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Pow: operator.pow,
        }
        return ops[type(node.op)](left, right)
    elif isinstance(node, ast.UnaryOp):
        operand = eval_node(node.operand)
        ops = {ast.UAdd: operator.pos, ast.USub: operator.neg}
        return ops[type(node.op)](operand)
    raise ValueError(f"Unsupported operation: {type(node)}")

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = safe_eval(expr)
        return {"result": result}
    except Exception as e:
        return {"error": str(e)}, 400

if __name__ == '__main__':
    app.run()
