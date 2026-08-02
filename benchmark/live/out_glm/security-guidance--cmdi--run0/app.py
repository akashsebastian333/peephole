import ipaddress
import re
import subprocess

from flask import Flask, request, jsonify

app = Flask(__name__)

# Hostnames: letters, digits, hyphens, dots; 1-253 chars total, no leading/trailing dot/hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z0-9-]{1,63}(?<!-)$"
)


def is_valid_host(host: str) -> bool:
    if not host:
        return False
    # Accept IP literals (v4/v6) ...
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # ... or a syntactically valid DNS hostname.
    return bool(_HOSTNAME_RE.match(host))


@app.get("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not is_valid_host(host):
        return jsonify({"error": "invalid or missing 'host' parameter"}), 400

    # No shell: host is passed as a list element, so it cannot break out into a
    # separate command/argument regardless of its content. Validation above is
    # defense-in-depth, not the primary control.
    try:
        completed = subprocess.run(
            ["ping", "-c", "4", host],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"host": host, "error": "ping timed out"}), 504
    except FileNotFoundError:
        return jsonify({"host": host, "error": "ping binary not found"}), 500

    return jsonify(
        {
            "host": host,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    )


if __name__ == "__main__":
    app.run()
