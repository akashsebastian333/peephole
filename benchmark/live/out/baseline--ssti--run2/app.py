from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = "Hello, {{ name }}!"
    return render_template_string(template, name=name)

if __name__ == '__main__':
    app.run()
