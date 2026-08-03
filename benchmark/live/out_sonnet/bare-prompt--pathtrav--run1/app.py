import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.abspath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.abspath(os.path.join(FILES_DIR, name))
    # ponytail: boundary check, not a sandbox — blocks ../ and absolute-path escapes
    if os.path.commonpath([path, FILES_DIR]) != FILES_DIR or not os.path.isfile(path):
        abort(404)
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run()
