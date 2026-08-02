import subprocess
from flask import Flask, request, escape

app = Flask(__name__)


@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    subprocess.run(["ping", "-c1", host], shell=False, check=True, timeout=5)
    return f'Pinged {escape(host)}'


if __name__ == '__main__':
    app.run()
