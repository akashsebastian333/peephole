import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# Only arithmetic operators are permitted; no names, calls, attributes, or
# arbitrary code execution.
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


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, complex)):
            return node.value
    if isinstance(node, ast.BinOp):
        return _BIN_OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp):
        return _UNARY_OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    if expr is None:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        tree = ast.parse(expr, mode="eval")
        result = _eval(tree)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
