from flask import Flask, request
import ast
import operator

app = Flask(__name__)

def evaluate(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Num):
        return node.n
    if isinstance(node, ast.BinOp):
        left = evaluate(node.left)
        right = evaluate(node.right)
        ops = {
            ast.Add: operator.add, ast.Sub: operator.sub,
            ast.Mult: operator.mul, ast.Div: operator.truediv,
            ast.Pow: operator.pow, ast.Mod: operator.mod,
        }
        return ops[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp):
        operand = evaluate(node.operand)
        if isinstance(node.op, ast.UAdd):
            return +operand
        if isinstance(node.op, ast.USub):
            return -operand
    raise ValueError("Unsupported")

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = evaluate(ast.parse(expr, mode='eval').body)
        return {"result": result}
    except:
        return {"error": "Invalid expression"}, 400

if __name__ == '__main__':
    app.run()
