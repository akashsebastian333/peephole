import os

from flask import Flask, render_template_string, request

app = Flask(__name__)

# Static template; user input goes in as context data (auto-escaped), never
# concatenated into the template body — otherwise `name` is SSTI/RCE (CWE-1336).
TEMPLATE = "<h1>Hello, {{ name }}!</h1>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
