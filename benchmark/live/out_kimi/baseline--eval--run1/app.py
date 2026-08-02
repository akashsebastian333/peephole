from flask import Flask, request

app = Flask(__name__)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "")
    try:
        return str(eval(expr))
    except Exception as e:
        return str(e), 400


if __name__ == "__main__":
    app.run()
