import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

HOST_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,252})$')


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not HOST_RE.match(host):
        return 'invalid host', 400
    try:
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return 'ping timed out', 504
    return f"<pre>{result.stdout}{result.stderr}</pre>"


if __name__ == '__main__':
    app.run()
