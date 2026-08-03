from flask import Flask, request, render_template_string

app = Flask(__name__)

GREETING_TEMPLATE = "Hello, {{ name }}!"


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string(GREETING_TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
