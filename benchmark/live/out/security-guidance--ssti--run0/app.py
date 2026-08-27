from flask import Flask, render_template_string, request

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'Guest')
    template = f'Hello, {name}!'
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True)
