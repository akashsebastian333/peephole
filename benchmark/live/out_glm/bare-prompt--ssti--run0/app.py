from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.get("/greet")
def greet():
    name = request.args.get("name", "")
    # Pass user input as a template variable, never concatenate it into the
    # template source. Jinja autoescapes {{ name }}, so this is safe from both
    # XSS and SSTI.
    return render_template_string("Hello, {{ name }}!", name=name)


if __name__ == "__main__":
    app.run()
