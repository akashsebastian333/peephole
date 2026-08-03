from flask import Flask, render_template_string, request

app = Flask(__name__)

TEMPLATE = "<h1>Hello, {{ name }}!</h1>"


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run()
