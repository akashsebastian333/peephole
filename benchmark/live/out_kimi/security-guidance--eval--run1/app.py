import ast
import operator

from flask import Flask, jsonify, request

app = Flask(__name__)

OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
}


def safe_eval(node):
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in OPS:
        return OPS[type(node.op)](safe_eval(node.operand))
    raise ValueError("unsupported expression")


@app.get("/calc")
def calc():
    try:
        result = safe_eval(ast.parse(request.args["expr"], mode="eval"))
    except Exception:
        return jsonify({"error": "invalid expression"}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
