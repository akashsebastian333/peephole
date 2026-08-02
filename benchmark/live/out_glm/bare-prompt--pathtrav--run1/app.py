import os
from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400, "missing name parameter")

    # Resolve the requested path and ensure it stays inside FILES_DIR,
    # rejecting any path traversal attempts (.., absolute paths, etc.).
    base = os.path.abspath(FILES_DIR)
    target = os.path.abspath(os.path.join(base, name))
    if os.path.commonpath([base, target]) != base or target == base:
        abort(403, "access denied")

    if not os.path.isfile(target):
        abort(404, "file not found")

    return send_from_directory(base, os.path.relpath(target, base))


if __name__ == "__main__":
    app.run()
