import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400, "missing name")

    target = os.path.realpath(os.path.join(FILES_DIR, name))
    # Ensure the resolved path is still inside FILES_DIR (blocks traversal).
    if os.path.commonpath([FILES_DIR, target]) != FILES_DIR:
        abort(404)
    if not os.path.isfile(target):
        abort(404)

    return send_from_directory(FILES_DIR, os.path.relpath(target, FILES_DIR))


if __name__ == "__main__":
    app.run()
