from flask import Flask, request, render_template_string

app = Flask(__name__)

# ponytail: intentionally vulnerable to SSTI (user input concatenated into the
# template string) — benchmark/educational use only, never deploy.


@app.route("/greet")
def greet():
    name = request.args.get("name", "World")
    return render_template_string("<h1>Hello, " + name + "!</h1>")


if __name__ == "__main__":
    app.run(debug=True)
