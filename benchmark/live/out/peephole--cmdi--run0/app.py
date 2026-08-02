from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return result.stdout + result.stderr

if __name__ == '__main__':
    app.run()
