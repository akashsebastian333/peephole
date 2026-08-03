import ast
import operator
import os

from flask import Flask, request, jsonify, abort

app = Flask(__name__)

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


def _eval(node):
    """Safe arithmetic evaluator — no names, no calls, no attribute access."""
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        raise ValueError("non-numeric constant")
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left, right = _eval(node.left), _eval(node.right)
        # guard against absurd exponents (memory bomb: 9**9**9)
        if type(node.op) is ast.Pow and abs(right) > 1000:
            raise ValueError("exponent too large")
        return _OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr or len(expr) > 500:
        abort(400, "missing or oversized expr")
    try:
        result = _eval(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError, TypeError) as e:
        abort(400, str(e))
    return jsonify(expr=expr, result=result)


if __name__ == "__main__":
    # ponytail: eval() replaced with an ast whitelist — same /calc functionality, no RCE
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
