import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.realpath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    requested = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([requested, FILES_DIR]) != FILES_DIR or not os.path.isfile(requested):
        abort(404)
    return send_from_directory(FILES_DIR, os.path.relpath(requested, FILES_DIR))


if __name__ == "__main__":
    app.run()
