from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = "<h1>Hello, {{ name }}!</h1>"


@app.get("/greet")
def greet():
    name = request.args.get("name", "world")
    # Pass `name` as a context variable; Jinja escapes it and never
    # evaluates it as a template expression (safe against SSTI).
    return render_template_string(TEMPLATE, name=name)


if __name__ == "__main__":
    app.run(debug=False)
