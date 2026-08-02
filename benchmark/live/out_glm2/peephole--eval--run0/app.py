import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# Only these operators and node types are permitted; everything else is rejected.
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


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError(f"unsupported operator: {type(node.op).__name__}")
        return op(_safe_eval(node.left), _safe_eval(node.right))
    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise ValueError(f"unsupported operator: {type(node.op).__name__}")
        return op(_safe_eval(node.operand))
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float, complex)):
            return node.value
        raise ValueError("only numeric constants are allowed")
    raise ValueError(f"unsupported expression element: {type(node).__name__}")


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    if expr is None:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        tree = ast.parse(expr, mode="eval")
        result = _safe_eval(tree)
    except (SyntaxError, ValueError, ZeroDivisionError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
