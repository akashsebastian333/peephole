from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")[:100]
    # ponytail: name passed as a template variable (autoescaped), never
    # concatenated into the template source — that would be SSTI/RCE.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


if __name__ == "__main__":
    app.run()
