import ast
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr")
    if expr is None:
        return jsonify({"error": "missing 'expr' query parameter"}), 400
    try:
        result = ast.literal_eval(expr)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"result": result})


if __name__ == "__main__":
    app.run()
