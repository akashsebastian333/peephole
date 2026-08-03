from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    return render_template_string("Hello, {{ name }}!", name=name)

if __name__ == "__main__":
    app.run()
