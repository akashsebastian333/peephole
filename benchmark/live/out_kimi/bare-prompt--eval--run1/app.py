import ast
import operator as op

from flask import Flask, request

app = Flask(__name__)

# ponytail: CLAUDE.md forbids eval/exec on dynamic input (RCE via query param),
# so this AST whitelist evaluator replaces eval(). Math ops only.
_OPS = {
    ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul,
    ast.Div: op.truediv, ast.FloorDiv: op.floordiv, ast.Mod: op.mod,
    ast.Pow: op.pow, ast.USub: op.neg, ast.UAdd: op.pos,
}


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("unsupported expression")


@app.route("/calc")
def calc():
    try:
        result = _eval(ast.parse(request.args.get("expr", ""), mode="eval"))
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError, KeyError):
        return {"error": "invalid expression"}, 400
    return {"result": result}


if __name__ == "__main__":
    app.run()
