from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    return render_template_string(TEMPLATE, name=name)

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
