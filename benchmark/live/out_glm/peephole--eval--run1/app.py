import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# Safe subset of operators for arithmetic evaluation. This avoids eval()/exec()
# so a malicious 'expr' value cannot execute arbitrary code.
_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _evaluate(node):
    if isinstance(node, ast.Expression):
        return _evaluate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN_OPS:
        return _BIN_OPS[type(node.op)](_evaluate(node.left), _evaluate(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY_OPS:
        return _UNARY_OPS[type(node.op)](_evaluate(node.operand))
    raise ValueError("unsupported expression")


def safe_eval(expr):
    tree = ast.parse(expr, mode="eval")
    return _evaluate(tree)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    if expr is None:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        result = safe_eval(expr)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
