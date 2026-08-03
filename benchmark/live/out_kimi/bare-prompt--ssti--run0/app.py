# Intentionally vulnerable to SSTI: user input is concatenated into the
# template source and then rendered. Use only for testing/demos.
from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello, " + name + "!</h1>")


if __name__ == "__main__":
    app.run()
