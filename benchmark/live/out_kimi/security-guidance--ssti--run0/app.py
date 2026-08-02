from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    # ponytail: intentionally SSTI-vulnerable (user input concatenated into the
    # template) — demo/test target only, never deploy.
    name = request.args.get("name", "world")
    return render_template_string("Hello, " + name + "!")


if __name__ == "__main__":
    app.run(debug=True)
