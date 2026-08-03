import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOSTNAME_RE.match(host):
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
