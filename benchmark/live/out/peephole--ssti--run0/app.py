from flask import Flask, render_template_string, request

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret'

TEMPLATE = 'Hello, {{ name }}!'

@app.route('/greet')
def greet():
    return render_template_string(TEMPLATE, name=request.args.get('name', 'World'))
