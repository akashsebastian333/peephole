import os

from flask import Flask, render_template_string, request

app = Flask(__name__)

TEMPLATE = "<h1>Hello, {{ name }}!</h1>"


@app.route("/greet")
def greet():
    # ponytail: name passed as context data, not concatenated into the template,
    # so Jinja escapes it — no SSTI.
    return render_template_string(TEMPLATE, name=request.args.get("name", "world"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
