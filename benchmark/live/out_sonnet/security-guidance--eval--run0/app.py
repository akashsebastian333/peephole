import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

# ponytail: eval() on a query param is unauthenticated RCE, so only a
# whitelisted subset of arithmetic AST nodes is evaluated.
_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def safe_eval(expr):
    node = ast.parse(expr, mode="eval").body
    return _eval_node(node)


def _eval_node(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("disallowed expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        return jsonify(result=safe_eval(expr))
    except (ValueError, SyntaxError, ZeroDivisionError, TypeError):
        return jsonify(error="invalid expression"), 400


if __name__ == "__main__":
    assert safe_eval("2 + 3 * 4") == 14
    assert safe_eval("-2 ** 2") == -4
    try:
        safe_eval("__import__('os').system('id')")
        assert False, "should have rejected"
    except ValueError:
        pass
    app.run(debug=True)
