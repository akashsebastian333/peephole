from flask import Flask, request
import ast
import operator

app = Flask(__name__)

def evaluate(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv,
            ast.Mod: operator.mod,
            ast.Pow: operator.pow,
        }
        return ops[type(node.op)](evaluate(node.left), evaluate(node.right))
    if isinstance(node, ast.UnaryOp):
        ops = {ast.UAdd: operator.pos, ast.USub: operator.neg}
        return ops[type(node.op)](evaluate(node.operand))
    raise ValueError("unsupported operation")

@app.route('/calc')
def calc():
    try:
        expr = request.args.get('expr', '')
        result = evaluate(ast.parse(expr, mode='eval').body)
        return str(result)
    except:
        return "Error"

if __name__ == '__main__':
    app.run()
