from flask import Flask, request, render_template_string

app = Flask(__name__)

TEMPLATE = "Hello {{ name }}!"

@app.route('/greet')
def greet():
    return render_template_string(TEMPLATE, name=request.args.get('name', 'Guest'))

if __name__ == '__main__':
    app.run()
