import ast
import operator
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

_BINOPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARYOPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def safe_eval(expr: str):
    """Evaluate an arithmetic expression; no names, calls, or attributes."""
    def walk(node):
        if isinstance(node, ast.Expression):
            return walk(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
            return _BINOPS[type(node.op)](walk(node.left), walk(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARYOPS:
            return _UNARYOPS[type(node.op)](walk(node.operand))
        raise ValueError("unsupported expression")

    return walk(ast.parse(expr, mode="eval"))


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        return jsonify({"result": safe_eval(expr)})
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError):
        return jsonify({"error": "invalid expression"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
