import ast
import operator as op

from flask import Flask, jsonify, request

app = Flask(__name__)

_OPS = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
    ast.Div: op.truediv, ast.FloorDiv: op.floordiv, ast.Mod: op.mod,
    ast.USub: op.neg, ast.UAdd: op.pos,
}


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Pow):
            base, exp = _eval(node.left), _eval(node.right)
            if abs(exp) > 1000:  # ponytail: pow DoS guard, tune if big exponents needed
                raise ValueError("exponent too large")
            return base**exp
        if type(node.op) in _OPS:
            return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    if len(expr) > 200:
        return jsonify(error="expression too long"), 400
    try:
        result = _eval(ast.parse(expr, mode="eval"))
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError, OverflowError):
        return jsonify(error="invalid expression"), 400
    return jsonify(result=result)


if __name__ == "__main__":
    app.run()
