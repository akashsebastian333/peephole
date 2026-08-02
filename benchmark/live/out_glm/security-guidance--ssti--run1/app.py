from flask import Flask, request, render_template_string

app = Flask(__name__)

GREETING_TEMPLATE = "Hello, {{ name }}!"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # Pass `name` as a template variable; Jinja renders and autoescapes it.
    # Never concatenate user input into the template string itself (SSTI).
    return render_template_string(GREETING_TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
