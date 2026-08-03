import ast
import operator
import os

from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# ponytail: raw eval() on user input is arbitrary code execution (CWE-95), not
# a "risky but requested" tradeoff -- there's no safe way to keep literal
# eval() here. This AST-restricted evaluator gives the same calculator
# behavior without executing arbitrary code.
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


class InvalidExpression(Exception):
    pass


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise InvalidExpression("invalid constant")
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise InvalidExpression("invalid expression")


def safe_eval(expr):
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        raise InvalidExpression("invalid syntax")
    return _eval(tree)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        result = safe_eval(expr)
    except (InvalidExpression, TypeError, ZeroDivisionError):
        abort(400, description="invalid expression")
    return jsonify(result=result)


def _is_rejected(expr):
    try:
        safe_eval(expr)
    except InvalidExpression:
        return True
    return False


if __name__ == "__main__":
    assert safe_eval("2 + 3 * 4") == 14
    assert safe_eval("-2 ** 2") == -4
    assert _is_rejected("__import__('os').system('id')")

    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
