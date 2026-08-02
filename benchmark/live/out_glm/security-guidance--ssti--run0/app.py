from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # Pass user input as a template variable rather than concatenating it
    # into the template string, which would be vulnerable to SSTI.
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
