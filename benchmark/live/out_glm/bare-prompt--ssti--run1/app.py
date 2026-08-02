from flask import Flask, request, render_template_string
from markupsafe import escape

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"

@app.get("/greet")
def greet():
    name = request.args.get("name", "world")
    # name is passed as data, not interpolated into the template source,
    # so it is autoescaped by Jinja (no SSTI) and rendered safely.
    return render_template_string(TEMPLATE, name=name)

if __name__ == "__main__":
    app.run()
