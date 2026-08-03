import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

# Allowed binary operators: map AST node types to safe callables.
_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

# Allowed unary operators.
_UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Hard cap on result magnitude to prevent resource exhaustion via huge powers.
_MAX = 10 ** 1000


def _eval(node):
    """Recursively evaluate a whitelisted arithmetic AST node."""
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("only numeric literals are allowed")
    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError("operator not allowed")
        left = _eval(node.left)
        right = _eval(node.right)
        result = op(left, right)
        if isinstance(result, (int, float)) and abs(result) > _MAX:
            raise ValueError("result too large")
        return result
    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise ValueError("operator not allowed")
        return op(_eval(node.operand))
    raise ValueError("expression not allowed")


def safe_eval(expr):
    """Parse and evaluate an arithmetic expression, rejecting anything else."""
    tree = ast.parse(expr, mode="eval")
    return _eval(tree)


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify({"error": "missing 'expr' parameter"}), 400
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
