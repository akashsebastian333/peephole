import ipaddress
import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.?)*[A-Za-z0-9]$")


def is_valid_host(host):
    if not host or len(host) > 253:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not is_valid_host(host):
        return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(host=host, reachable=result.returncode == 0, output=result.stdout)


if __name__ == "__main__":
    app.run()
