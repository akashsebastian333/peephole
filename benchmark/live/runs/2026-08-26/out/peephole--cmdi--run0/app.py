from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host:
        return 'Missing host parameter', 400

    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return result.stdout or result.stderr, result.returncode

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=False)
