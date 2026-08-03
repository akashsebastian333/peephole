from flask import Flask, request, render_template_string

app = Flask(__name__)


# ponytail: intentionally SSTI-vulnerable (user input concatenated into the
# template source) — security demo/educational use only, never deploy as-is.
@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


if __name__ == "__main__":
    app.run(debug=True)
