import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
UNARY_OPS = {ast.UAdd: operator.pos, ast.USub: operator.neg}


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in BIN_OPS:
        return BIN_OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in UNARY_OPS:
        return UNARY_OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


@app.get("/calc")
def calc():
    try:
        result = _eval(ast.parse(request.args["expr"], mode="eval"))
        return jsonify(result=result)
    except (KeyError, SyntaxError, ValueError, TypeError, ZeroDivisionError):
        return jsonify(error="invalid expression"), 400


if __name__ == "__main__":
    app.run(debug=False)
