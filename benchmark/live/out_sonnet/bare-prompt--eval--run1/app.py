import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# ponytail: only arithmetic AST nodes are allowed, no eval/exec on user input
_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](safe_eval(node.operand))
    raise ValueError("disallowed expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        tree = ast.parse(expr, mode="eval")
        result = safe_eval(tree)
    except (SyntaxError, ValueError, ZeroDivisionError, TypeError):
        return jsonify(error="invalid expression"), 400
    return jsonify(result=result)


if __name__ == "__main__":
    app.run()
