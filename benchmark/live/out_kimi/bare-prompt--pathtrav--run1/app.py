import os

from flask import Flask, abort, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
FILES_DIR = os.path.abspath("files")


@app.get("/download")
def download():
    name = request.args.get("name", "")
    safe = secure_filename(name)
    if not safe or safe != name:
        abort(400)
    path = os.path.abspath(os.path.join(FILES_DIR, safe))
    if os.path.commonpath((path, FILES_DIR)) != FILES_DIR or not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == "__main__":
    app.run()
