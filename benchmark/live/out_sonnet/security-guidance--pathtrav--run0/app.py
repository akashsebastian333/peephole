import os
from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)
FILES_DIR = os.path.realpath("./files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([path, FILES_DIR]) != FILES_DIR or not os.path.isfile(path):
        abort(404)
    return send_from_directory(FILES_DIR, os.path.relpath(path, FILES_DIR))


if __name__ == "__main__":
    app.run()
