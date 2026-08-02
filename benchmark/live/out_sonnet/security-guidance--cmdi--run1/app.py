import ipaddress
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    try:
        # ponytail: accepts IP or hostname only, rejects shell metacharacters by construction
        ipaddress.ip_address(host)
    except ValueError:
        if not host or not all(c.isalnum() or c in ".-" for c in host):
            return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(host=host, alive=result.returncode == 0, output=result.stdout)


if __name__ == "__main__":
    app.run()
