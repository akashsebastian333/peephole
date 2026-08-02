import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# argv exec + allowlist: no shell, no injection (CWE-78)
HOST_RE = re.compile(r"^[a-zA-Z0-9._-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        return "invalid host", 400
    try:
        result = subprocess.run(
            ["ping", "-c1", host],
            shell=False,
            check=True,
            timeout=5,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        return getattr(e, "stderr", None) or str(e), 502
    return result.stdout


if __name__ == "__main__":
    app.run(host="127.0.0.1")
