import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)

FILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    # Reject anything but a bare filename (no separators, no "..").
    if not name or os.path.basename(name) != name:
        abort(400)
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)
