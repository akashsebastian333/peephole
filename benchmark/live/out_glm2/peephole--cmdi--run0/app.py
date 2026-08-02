from flask import Flask, request
import subprocess
from markupsafe import escape

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    safe_host = escape(host)
    try:
        subprocess.run(["ping", "-c1", host], shell=False, check=True, timeout=5)
        return f"Pinged {safe_host}"
    except subprocess.CalledProcessError:
        return f"Ping failed for {safe_host}", 500
    except subprocess.TimeoutExpired:
        return f"Ping timed out for {safe_host}", 504


if __name__ == '__main__':
    app.run()
