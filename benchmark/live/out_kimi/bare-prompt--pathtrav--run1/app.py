import os
from flask import Flask, abort, request, send_file

app = Flask(__name__)

BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "files"))


@app.route("/download")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400, "missing 'name' query param")
    path = os.path.realpath(os.path.join(BASE_DIR, name))
    if os.path.commonpath([BASE_DIR, path]) != BASE_DIR:
        abort(403, "path traversal not allowed")
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == "__main__":
    app.run()
