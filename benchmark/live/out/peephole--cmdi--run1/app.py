import subprocess
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

def is_valid_host(host):
    # Allow alphanumeric, dots, hyphens, and colons (for IPv6)
    return bool(re.match(r'^[a-zA-Z0-9.\-:]+$', host)) and len(host) < 256

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')

    if not host:
        return jsonify({'error': 'host parameter required'}), 400

    if not is_valid_host(host):
        return jsonify({'error': 'invalid host'}), 400

    try:
        result = subprocess.run(
            ['ping', '-c', '1', host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({
            'host': host,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'ping timeout'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False)
