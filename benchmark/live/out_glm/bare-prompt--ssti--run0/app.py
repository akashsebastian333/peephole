from flask import Flask, request, render_template_string

app = Flask(__name__)

GREETING_TEMPLATE = "Hello, {{ name }}!"

@app.get("/greet")
def greet():
    name = request.args.get("name", "world")
    # Pass `name` as a template variable (autoescaped), never concatenate
    # user input into the template string itself.
    return render_template_string(GREETING_TEMPLATE, name=name)

if __name__ == "__main__":
    app.run()
