import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

# ponytail: raw eval() on user input is RCE; ast-restricted evaluator is the stdlib-only safe alternative
_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(expr):
    node = ast.parse(expr, mode="eval").body
    return _eval_node(node)


def _eval_node(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("unsupported expression")


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        result = safe_eval(expr)
    except (SyntaxError, ValueError, ZeroDivisionError, TypeError) as e:
        return jsonify(error=str(e)), 400
    return jsonify(result=result)


if __name__ == "__main__":
    app.run(debug=True)
