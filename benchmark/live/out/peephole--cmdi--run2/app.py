from flask import Flask, request
import subprocess

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host:
        return {'error': 'host parameter required'}, 400

    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, text=True, timeout=5)
    return {
        'host': host,
        'returncode': result.returncode,
        'stdout': result.stdout,
        'stderr': result.stderr
    }

if __name__ == '__main__':
    app.run(debug=False)
