import ast
import math
import operator
from flask import Flask, request, jsonify

app = Flask(__name__)

# Safe operator mapping for binary operations.
BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

UNARY_OPS = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}

# Safe callable names exposed to expressions.
SAFE_FUNCS = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "sum": sum,
    "pow": pow,
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "log": math.log,
    "log10": math.log10,
    "exp": math.exp,
    "floor": math.floor,
    "ceil": math.ceil,
}

SAFE_CONSTS = {
    "pi": math.pi,
    "e": math.e,
}


def _eval_node(node):
    """Safely evaluate a restricted AST expression tree."""
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return node.value
        raise ValueError("unsupported constant")
    if isinstance(node, ast.BinOp):
        op = BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError("unsupported binary operator")
        return op(_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp):
        op = UNARY_OPS.get(type(node.op))
        if op is None:
            raise ValueError("unsupported unary operator")
        return op(_eval_node(node.operand))
    if isinstance(node, ast.Call):
        if not isinstance(node.func, ast.Name):
            raise ValueError("unsupported call target")
        func = SAFE_FUNCS.get(node.func.id)
        if func is None:
            raise ValueError(f"function not allowed: {node.func.id}")
        args = [_eval_node(a) for a in node.args]
        return func(*args)
    if isinstance(node, ast.Name):
        if node.id in SAFE_CONSTS:
            return SAFE_CONSTS[node.id]
        raise ValueError(f"name not allowed: {node.id}")
    raise ValueError("unsupported expression node")


def safe_eval(expr):
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        result = safe_eval(expr)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
