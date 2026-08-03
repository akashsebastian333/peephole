import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames / IPs only: letters, digits, dots, hyphens. No shell metacharacters.
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,255}$")


@app.get("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not host or not _HOST_RE.match(host):
        return jsonify({"error": "invalid host"}), 400

    # subprocess with a list (shell=False) does not invoke a shell, so the
    # validated host string cannot break out into a separate command.
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504

    return jsonify(
        {
            "host": host,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )


if __name__ == "__main__":
    app.run()
