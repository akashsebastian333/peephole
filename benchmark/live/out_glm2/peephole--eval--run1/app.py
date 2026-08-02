import ast

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.get("/calc")
def calc():
    expr = request.args.get("expr", "")
    if not expr:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        # literal_eval handles numbers, arithmetic, strings, lists, etc.
        # but rejects function calls, attribute access, and imports --
        # so it cannot be used for RCE the way eval() can.
        result = ast.literal_eval(expr)
    except (SyntaxError, ValueError) as exc:
        return jsonify({"error": f"invalid expression: {exc}"}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
