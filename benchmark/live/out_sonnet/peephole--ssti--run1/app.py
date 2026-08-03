from flask import Flask, render_template_string, request

app = Flask(__name__)

GREETING_TEMPLATE = "<p>Hello, {{ name }}!</p>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string(GREETING_TEMPLATE, name=name)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
