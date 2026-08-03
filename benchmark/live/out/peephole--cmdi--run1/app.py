import subprocess
import re
from flask import Flask, request

app = Flask(__name__)

@app.route('/ping')
def ping():
    host = request.args.get('host', '')

    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return {'error': 'invalid host'}, 400

    result = subprocess.run(['ping', '-c', '1', host], capture_output=True, timeout=5)
    return {'returncode': result.returncode, 'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()}

if __name__ == '__main__':
    app.run()
