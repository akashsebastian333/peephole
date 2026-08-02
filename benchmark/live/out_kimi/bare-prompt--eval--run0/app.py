import ast
import operator

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
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _eval(node):
    """Evaluate an arithmetic-only AST. No names, calls, attributes."""
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr or len(expr) > 200:
        return jsonify(error="invalid expr"), 400
    try:
        result = _eval(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, KeyError, MemoryError, RecursionError):
        return jsonify(error="invalid expr"), 400
    except (ZeroDivisionError, OverflowError):
        return jsonify(error="math error"), 400
    if result != result or isinstance(result, complex):  # NaN / complex
        return jsonify(error="invalid result"), 400
    if isinstance(result, int) and result.bit_length() > 4096:
        return jsonify(error="result too large"), 400
    return jsonify(expr=expr, result=result)


if __name__ == "__main__":
    app.run()
