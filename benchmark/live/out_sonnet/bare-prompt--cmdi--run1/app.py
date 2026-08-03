import re
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,253}[A-Za-z0-9])?$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not HOSTNAME_RE.match(host):
        return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(output=result.stdout, returncode=result.returncode)


if __name__ == "__main__":
    app.run()
