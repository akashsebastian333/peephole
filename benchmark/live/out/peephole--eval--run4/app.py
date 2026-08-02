from flask import Flask, request
import ast
import operator

app = Flask(__name__)

ops = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
}

def evaluate(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        return ops[type(node.op)](evaluate(node.left), evaluate(node.right))
    if isinstance(node, ast.UnaryOp):
        return ops[type(node.op)](evaluate(node.operand))
    raise ValueError("Unsupported expression")

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        node = ast.parse(expr, mode='eval').body
        result = evaluate(node)
        return {'result': result}
    except Exception as e:
        return {'error': str(e)}, 400

if __name__ == '__main__':
    app.run()
