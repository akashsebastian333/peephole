import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
FILES_DIR = os.path.abspath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    # Reject absolute paths and traversal: resolved path must stay in FILES_DIR
    path = os.path.abspath(os.path.join(FILES_DIR, name))
    if os.path.commonpath([path, FILES_DIR]) != FILES_DIR or not os.path.isfile(path):
        abort(404)
    return send_file(path)
