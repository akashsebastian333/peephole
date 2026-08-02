from flask import Flask, request
import ast
import operator

app = Flask(__name__)

SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def eval_ast(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.BinOp):
        left = eval_ast(node.left)
        right = eval_ast(node.right)
        return SAFE_OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp):
        operand = eval_ast(node.operand)
        return SAFE_OPS[type(node.op)](operand)
    raise ValueError("Unsupported operation")

def safe_eval(expr):
    tree = ast.parse(expr, mode='eval')
    return eval_ast(tree.body)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        return {'result': safe_eval(expr)}
    except Exception as e:
        return {'error': str(e)}, 400

if __name__ == '__main__':
    app.run()
