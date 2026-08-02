import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    if not host:
        return "Missing 'host' parameter", 400
    try:
        subprocess.run(["ping", "-c1", host], shell=False, check=True, timeout=5)
    except subprocess.CalledProcessError:
        return f"Ping to {host} failed", 502
    except subprocess.TimeoutExpired:
        return f"Ping to {host} timed out", 504
    return f"Pinged {host}"


if __name__ == "__main__":
    app.run()
