from flask import Flask, render_template_string, request
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    return render_template_string("Hello {{ name }}!", name=name)

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1', host='127.0.0.1')
