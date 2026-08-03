import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.get("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and ensure it stays within FILES_DIR,
    # preventing path traversal (e.g. name="../../etc/passwd").
    base = os.path.realpath(FILES_DIR)
    target = os.path.realpath(os.path.join(base, name))
    if base != os.path.commonpath([base, target]):
        abort(403, "forbidden")

    if not os.path.isfile(target):
        abort(404, "not found")

    return send_from_directory(base, os.path.relpath(target, base))


if __name__ == "__main__":
    app.run()
