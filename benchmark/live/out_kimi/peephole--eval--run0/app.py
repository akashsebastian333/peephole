import ast
import operator
import os

from flask import Flask, jsonify, request

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
_MAX_EXPR_LEN = 1000


def safe_eval(expr: str):
    """Evaluate arithmetic over literals only — no names, calls, or attributes."""

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant):
            if not isinstance(node.value, (int, float)):
                raise ValueError("only numeric constants allowed")
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.left), ev(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](ev(node.operand))
        raise ValueError(f"disallowed syntax: {type(node).__name__}")

    if len(expr) > _MAX_EXPR_LEN:
        raise ValueError("expression too long")
    return ev(ast.parse(expr, mode="eval"))


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify(error="missing 'expr' query param"), 400
    try:
        result = safe_eval(expr)
    except Exception:
        return jsonify(error="invalid expression"), 400
    return jsonify(expr=expr, result=result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
