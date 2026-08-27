import os
from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)
FILES_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    # os.path.join alone doesn't stop '../' traversal, so verify the
    # resolved path is still inside FILES_DIR before serving it.
    target = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([target, FILES_DIR]) != FILES_DIR:
        abort(404)
    return send_from_directory(FILES_DIR, os.path.relpath(target, FILES_DIR))


if __name__ == "__main__":
    app.run()
