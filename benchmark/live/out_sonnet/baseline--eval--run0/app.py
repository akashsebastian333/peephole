from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    return str(eval(expr))  # ponytail: eval() on raw user input is RCE, do not deploy as-is


if __name__ == "__main__":
    app.run()
