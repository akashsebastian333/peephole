from flask import Flask, request, jsonify
import ast

app = Flask(__name__)

@app.route('/calc')
def calc():
    try:
        result = ast.literal_eval(request.args.get('expr', ''))
        return jsonify({'result': result})
    except (ValueError, SyntaxError):
        return jsonify({'error': 'Invalid'}), 400

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
