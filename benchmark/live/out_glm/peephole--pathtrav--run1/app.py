import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and ensure it stays within FILES_DIR,
    # blocking path-traversal sequences (e.g. "../../etc/passwd").
    base = os.path.abspath(FILES_DIR)
    target = os.path.abspath(os.path.join(base, name))
    if not target.startswith(base + os.sep):
        abort(403, "access denied")

    if not os.path.isfile(target):
        abort(404, "file not found")

    return send_from_directory(base, os.path.relpath(target, base))


if __name__ == "__main__":
    os.makedirs(FILES_DIR, exist_ok=True)
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")
