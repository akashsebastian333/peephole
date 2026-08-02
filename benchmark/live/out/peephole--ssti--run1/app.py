from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    template = 'Hello, {{ name }}!'
    return render_template_string(template, name=request.args.get('name', 'Guest'))

if __name__ == '__main__':
    app.run(host="127.0.0.1", debug=False)
