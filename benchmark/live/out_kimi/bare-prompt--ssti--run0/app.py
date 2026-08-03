from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # ponytail: name passed as template data, not concatenated — SSTI-safe
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


if __name__ == "__main__":
    app.run()
