from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"


@app.get("/greet")
def greet():
    name = request.args.get("name", "world")
    # Pass user input as a context variable rather than concatenating it into
    # the template source, so it is auto-escaped and cannot be interpreted as
    # Jinja syntax (prevents server-side template injection).
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
