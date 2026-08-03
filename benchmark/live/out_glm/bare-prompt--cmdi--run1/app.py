import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostname or IPv4/IPv6 literal; rejects shell metacharacters and spaces.
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$")


@app.get("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not host or not _HOST_RE.match(host) or len(host) > 253:
        return jsonify({"error": "invalid host"}), 400

    # Argument list => no shell interpretation, no injection.
    try:
        result = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"host": host, "error": "timeout"}), 504

    return jsonify(
        {
            "host": host,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )


if __name__ == "__main__":
    app.run(debug=False)
