from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # SSTI benchmark fixture: name is concatenated directly into the template
    return render_template_string("Hello, " + name + "!")


if __name__ == "__main__":
    app.run(debug=True)
