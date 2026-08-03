from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

GREETING_TEMPLATE = "Hello, {{ name }}!"

MAX_NAME_LEN = 80


@app.get("/greet")
def greet():
    raw_name = request.args.get("name", "world")
    # Validate at the boundary: keep it short and printable.
    name = raw_name.strip()[:MAX_NAME_LEN] or "world"
    # Pass user input as a template *variable*, never concatenate it into
    # the template source. Jinja autoescapes {{ name }} for the HTML sink.
    return render_template_string(GREETING_TEMPLATE, name=name)


if __name__ == "__main__":
    app.run(debug=False)
