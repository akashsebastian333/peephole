import re
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)

# Strict allowlist: hostname or IPv4/IPv6 only. No shell metacharacters can match.
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
_IPv4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _validate_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if _IPv4_RE.match(host):
        return all(0 <= int(o) <= 255 for o in host.split("."))
    return bool(_HOST_RE.match(host))


@app.route("/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not _validate_host(host):
        abort(400, "invalid host")
    # No shell: arguments passed as a list, so the validated host cannot break out.
    result = subprocess.run(
        ["ping", "-c", "4", host],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return {
        "host": host,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


if __name__ == "__main__":
    app.run()
