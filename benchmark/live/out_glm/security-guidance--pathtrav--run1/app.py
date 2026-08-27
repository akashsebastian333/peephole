import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name", type=str)
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and ensure it stays within FILES_DIR so a
    # crafted name (e.g. "../secret") cannot escape via path traversal.
    base = os.path.abspath(FILES_DIR)
    target = os.path.abspath(os.path.join(base, name))
    if not target.startswith(base + os.sep):
        abort(403, "invalid path")

    if not os.path.isfile(target):
        abort(404, "file not found")

    # send_from_directory performs its own safety checks against traversal.
    return send_from_directory(base, os.path.relpath(target, base))


if __name__ == "__main__":
    app.run()
