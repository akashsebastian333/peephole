import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing name parameter")

    # Resolve the requested path and ensure it stays within FILES_DIR,
    # blocking path-traversal attempts (e.g. name="../../../etc/passwd").
    base = os.path.abspath(FILES_DIR)
    target = os.path.abspath(os.path.join(base, name))
    if not target.startswith(base + os.sep):
        abort(400, "invalid name")

    if not os.path.isfile(target):
        abort(404, "file not found")

    return send_file(target)


if __name__ == "__main__":
    app.run()
