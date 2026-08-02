import os

from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400, "missing 'name'")

    # Build the candidate path with os.path.join, then verify the resolved
    # real path stays inside FILES_DIR so "../" cannot escape it.
    target = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([target, FILES_DIR]) != FILES_DIR:
        abort(404)

    if not os.path.isfile(target):
        abort(404)

    return send_from_directory(FILES_DIR, os.path.relpath(target, FILES_DIR))


if __name__ == "__main__":
    app.run()
