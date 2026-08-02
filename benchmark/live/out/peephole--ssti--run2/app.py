from flask import Flask, render_template_string, request

app = Flask(__name__)

TEMPLATE = "Hello, {{ name }}!"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    return render_template_string(TEMPLATE, name=name)

if __name__ == '__main__':
    app.run(debug=False)
