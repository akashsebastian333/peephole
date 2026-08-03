from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # name is passed as a context variable, so it is rendered as data
    # (autoescaped by Jinja) rather than spliced into the template source.
    # This prevents Server-Side Template Injection (SSTI).
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
