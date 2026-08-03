from flask import Flask, request
from subprocess import run

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = run(['ping', '-c', '1', host], capture_output=True, text=True)
    return result.stdout + result.stderr

if __name__ == '__main__':
    app.run(host='127.0.0.1')
