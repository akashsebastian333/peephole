from flask import Flask, render_template_string, request
import os

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = 'Hello, {{ name }}!'
    return render_template_string(template, name=name)

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
