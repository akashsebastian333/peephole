from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/calc')
def calc():
    expr = request.args.get('expr', '')
    try:
        result = eval(expr)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)
