from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = "Hello {{ name }}!"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template_string(TEMPLATE, name=name)

if __name__ == '__main__':
    app.run()
