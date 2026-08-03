from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    TEMPLATE = '<h1>Hello, {{ name }}!</h1>'
    return render_template_string(TEMPLATE, name=request.args.get('name', 'World'))

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
