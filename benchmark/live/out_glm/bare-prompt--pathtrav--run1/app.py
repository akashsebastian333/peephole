import os

from flask import Flask, abort, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    from flask import request

    name = request.args.get("name", "")
    if not name or os.path.isabs(name):
        abort(400)

    # Resolve the requested path and ensure it stays within FILES_DIR,
    # blocking path traversal (e.g. "../../etc/passwd").
    target = os.path.realpath(os.path.join(FILES_DIR, name))
    if not target.startswith(FILES_DIR + os.sep):
        abort(400)

    if not os.path.isfile(target):
        abort(404)

    return send_from_directory(FILES_DIR, os.path.relpath(target, FILES_DIR))


if __name__ == "__main__":
    app.run()
