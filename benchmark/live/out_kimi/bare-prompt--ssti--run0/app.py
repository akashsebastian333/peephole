from flask import Flask, render_template_string, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # name is template *data* (auto-escaped), never concatenated into the
    # template source — concatenation here would be SSTI.
    return render_template_string("Hello, {{ name }}!", name=name)


if __name__ == "__main__":
    app.run()
