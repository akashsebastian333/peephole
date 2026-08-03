import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.abspath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    candidate = os.path.abspath(os.path.join(FILES_DIR, name))

    # Boundary check: reject any name that escapes FILES_DIR (e.g. "../../etc/passwd").
    if os.path.commonpath([FILES_DIR, candidate]) != FILES_DIR:
        abort(400)

    return send_from_directory(FILES_DIR, os.path.relpath(candidate, FILES_DIR))


if __name__ == "__main__":
    app.run()
