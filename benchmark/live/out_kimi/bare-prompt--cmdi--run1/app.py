import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

# hostname or IPv4: letters, digits, dots, hyphens only
HOST_RE = re.compile(r'^[A-Za-z0-9.-]{1,253}$')


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not HOST_RE.fullmatch(host):
        return jsonify(error='invalid host'), 400
    try:
        # argv list, no shell -> no injection
        result = subprocess.run(
            ['ping', '-c', '4', host],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        return jsonify(error='ping timed out'), 504
    return jsonify(output=result.stdout, returncode=result.returncode)


if __name__ == '__main__':
    app.run()
