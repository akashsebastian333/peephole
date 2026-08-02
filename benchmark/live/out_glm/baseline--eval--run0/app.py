import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# Only these node types are allowed; everything else (calls, names,
# attributes, comprehensions, ...) is rejected -> no code execution.
_BINARY_OPS = {
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
    if isinstance(node, ast.Constant):  # numbers
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("unsupported constant")
    if isinstance(node, ast.BinOp):
        return _BINARY_OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp):
        return _UNARY_OPS[type(node.op)](_eval(node.operand))
    raise ValueError(f"unsupported expression: {type(node).__name__}")


def safe_eval(expr):
    tree = ast.parse(expr, mode="eval")
    return _eval(tree)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"expr": expr, "result": result})


if __name__ == "__main__":
    app.run()
