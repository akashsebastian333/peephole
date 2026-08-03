from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)


if __name__ == "__main__":
    app.run()
