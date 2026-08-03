import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)

FILES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Reject any NUL bytes outright.
    if "\x00" in name:
        abort(400, "invalid 'name' parameter")

    # Resolve the requested path relative to the files directory and ensure
    # the result stays inside it, blocking path traversal (e.g. "../secret").
    target = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([FILES_DIR, target]) != FILES_DIR:
        abort(403, "access denied")

    if not os.path.isfile(target):
        abort(404, "file not found")

    return send_file(target)


if __name__ == "__main__":
    app.run()
