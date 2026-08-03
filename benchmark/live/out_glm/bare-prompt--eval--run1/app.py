import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

# Only these operators are permitted; everything else is rejected.
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


def _eval_node(node):
    """Safely evaluate an arithmetic AST node. Raises on anything unsafe."""
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("only numeric constants are allowed")
    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError(f"unsupported operator: {type(node.op).__name__}")
        return op(_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        op = _UNARY_OPS.get(type(node.op))
        if op is None:
            raise ValueError(f"unsupported operator: {type(node.op).__name__}")
        return op(_eval_node(node.operand))
    raise ValueError(f"unsupported expression element: {type(node).__name__}")


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify(error="missing 'expr' parameter"), 400
    try:
        tree = ast.parse(expr, mode="eval")
        result = _eval_node(tree)
    except (ValueError, SyntaxError, ZeroDivisionError, OverflowError) as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(expr=expr, result=result)
