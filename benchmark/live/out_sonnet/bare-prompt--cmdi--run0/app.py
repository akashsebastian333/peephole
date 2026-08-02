import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# ponytail: RFC-1123-ish hostname/IPv4 allowlist regex, swap for a stricter parser if IPv6 is needed
HOST_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")


@app.get("/ping")
def ping():
    host = request.args.get("host", "")
    if not host or not HOST_RE.match(host):
        return jsonify(error="invalid host"), 400

    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        timeout=5,
    )
    return jsonify(host=host, output=result.stdout, returncode=result.returncode)


if __name__ == "__main__":
    app.run()
