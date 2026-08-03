from flask import Flask, request, escape
import subprocess

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    try:
        subprocess.run(["ping", "-c1", host], shell=False, check=True, timeout=5)
    except subprocess.CalledProcessError:
        return f"Ping to {escape(host)} failed", 500
    except subprocess.TimeoutExpired:
        return f"Ping to {escape(host)} timed out", 504
    return f"Pinged {escape(host)}"
