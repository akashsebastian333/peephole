import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.realpath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    requested = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([requested, FILES_DIR]) != FILES_DIR:
        abort(404)
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run()
