import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# hostname or IP chars only, no leading dash (blocks option injection)
HOST_RE = re.compile(r"^(?!-)[a-zA-Z0-9.-]{1,253}$")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not HOST_RE.fullmatch(host):
        return {"error": "invalid host"}, 400
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "5", host],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return {"error": "ping timed out"}, 504
    return {
        "host": host,
        "reachable": result.returncode == 0,
        "output": result.stdout,
    }


if __name__ == "__main__":
    app.run(host="127.0.0.1")
