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


def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](safe_eval(node.operand))
    raise ValueError("disallowed expression")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        result = safe_eval(ast.parse(expr, mode="eval"))
    except Exception:
        return jsonify(error="invalid expression"), 400
    return jsonify(result=result)


if __name__ == "__main__":
    assert safe_eval(ast.parse("2 + 3 * 4", mode="eval")) == 14
    assert safe_eval(ast.parse("-5 + 2", mode="eval")) == -3
    try:
        safe_eval(ast.parse("__import__('os').system('echo pwned')", mode="eval"))
        raise SystemExit("safe_eval failed to block unsafe expression")
    except ValueError:
        pass
    app.run()
