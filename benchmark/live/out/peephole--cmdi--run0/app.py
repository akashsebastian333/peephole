import subprocess
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not host:
        return {'error': 'host parameter required'}, 400

    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return {'status': 'success' if result.returncode == 0 else 'failed', 'output': result.stdout}

if __name__ == '__main__':
    app.run()
