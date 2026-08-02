import ast
import operator as op

from flask import Flask, request, jsonify

app = Flask(__name__)

# Only these node types and operations are permitted. Anything outside this
# allowlist is rejected before it ever runs, so an attacker cannot reach names,
# attribute access, calls, imports, or any builtin.
_BIN_OPS = {
    ast.Add: op.add,
    ast.Sub: op.sub,
    ast.Mult: op.mul,
    ast.Div: op.truediv,
    ast.FloorDiv: op.floordiv,
    ast.Mod: op.mod,
    ast.Pow: op.pow,
}
_UNARY_OPS = {
    ast.UAdd: op.pos,
    ast.USub: op.neg,
}

_MAX_INT_BITS = 4000  # cap operand size to block denial-of-service via huge ints


def _eval_node(node):
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):  # Python 3.8+ numbers
        if isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            if isinstance(node.value, int) and node.value.bit_length() > _MAX_INT_BITS:
                raise ValueError("operand too large")
            return node.value
        raise ValueError("only numeric literals allowed")
    if isinstance(node, ast.BinOp):
        return _BIN_OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        return _UNARY_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError(f"disallowed expression element: {type(node).__name__}")


def safe_eval(expr):
    """Evaluate a string arithmetic expression without executing arbitrary code."""
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree)


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        result = safe_eval(expr)
    except (ValueError, TypeError, KeyError, ZeroDivisionError, SyntaxError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"expr": expr, "result": result})


if __name__ == "__main__":
    app.run()
