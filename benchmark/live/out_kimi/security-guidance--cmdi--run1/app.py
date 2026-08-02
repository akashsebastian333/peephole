import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

HOST_RE = re.compile(r'^[a-zA-Z0-9._:-]+$')  # hostnames, IPv4, IPv6


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not HOST_RE.fullmatch(host):
        return jsonify({'error': 'invalid host'}), 400
    try:
        # no shell: args passed as a list, so host can't inject commands
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True, text=True, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'ping timed out'}), 504
    return jsonify({'host': host, 'ok': result.returncode == 0, 'output': result.stdout})


if __name__ == '__main__':
    app.run()
