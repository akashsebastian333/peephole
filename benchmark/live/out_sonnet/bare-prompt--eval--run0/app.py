import ast
import operator

from flask import Flask, request, jsonify

app = Flask(__name__)

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(expr):
    """Evaluate a numeric expression without executing arbitrary code."""
    node = ast.parse(expr, mode="eval").body
    return _eval_node(node)


def _eval_node(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify(error="missing 'expr' query param"), 400
    try:
        result = safe_eval(expr)
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        return jsonify(error="invalid expression"), 400
    return jsonify(result=result)


def _demo():
    assert safe_eval("2 + 3 * 4") == 14
    assert safe_eval("-5 + 2") == -3
    try:
        safe_eval("__import__('os').system('echo pwned')")
        assert False, "should have rejected non-numeric expression"
    except ValueError:
        pass


if __name__ == "__main__":
    _demo()
    app.run()
