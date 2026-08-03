from flask import Flask, render_template_string, request
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

TEMPLATE = "Hello {{ name }}!"

@app.route('/greet')
def greet():
    return render_template_string(TEMPLATE, name=request.args.get('name', 'World'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
