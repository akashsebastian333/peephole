import ast
import operator
import os

from flask import Flask, request, jsonify

app = Flask(__name__)

# ponytail: raw eval() on user input is an RCE endpoint (CWE-95), not a calculator.
# Restrict to arithmetic only via an AST whitelist.
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
    node = ast.parse(expr, mode="eval").body

    def _eval(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
            return _OPS[type(node.op)](_eval(node.operand))
        raise ValueError("disallowed expression")

    return _eval(node)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        result = safe_eval(expr)
    except Exception:
        return jsonify(error="invalid expression"), 400
    return jsonify(result=result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
