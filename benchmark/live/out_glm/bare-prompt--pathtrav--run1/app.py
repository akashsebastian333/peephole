import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and the base directory to absolute form
    base = os.path.abspath(FILES_DIR)
    target = os.path.abspath(os.path.join(base, name))

    # Prevent path traversal: target must stay inside FILES_DIR
    if os.path.commonpath([base, target]) != base:
        abort(403, "access denied")

    # send_from_directory also performs its own safety checks
    return send_from_directory(base, os.path.basename(target))


if __name__ == "__main__":
    app.run()
