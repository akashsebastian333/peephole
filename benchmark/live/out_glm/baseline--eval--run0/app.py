import ast
import operator as op
from flask import Flask, request, jsonify

app = Flask(__name__)

# Supported binary operators.
_BIN_OPS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.FloorDiv: op.floordiv,
    ast.Mod: op.mod,
    ast.Pow: op.pow,
}

# Supported unary operators.
_UNARY_OPS = {
    ast.UAdd: op.pos,
    ast.USub: op.neg,
}


def _eval(node):
    """Safely evaluate an AST node limited to numeric arithmetic."""
    if isinstance(node, ast.Constant):  # numbers
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        raise ValueError("invalid constant")
    if isinstance(node, ast.BinOp):
        fn = _BIN_OPS.get(type(node.op))
        if fn is None:
            raise ValueError("unsupported operator")
        return fn(_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp):
        fn = _UNARY_OPS.get(type(node.op))
        if fn is None:
            raise ValueError("unsupported operator")
        return fn(_eval(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        tree = ast.parse(expr, mode="eval")
        result = _eval(tree.body)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
