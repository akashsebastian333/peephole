import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


def safe_eval(expr):
    return _eval(ast.parse(expr, mode="eval").body)


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        return jsonify(result=safe_eval(expr))
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        return jsonify(error="invalid expression"), 400


if __name__ == "__main__":
    app.run()
