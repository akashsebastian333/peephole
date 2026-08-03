import os
from flask import Flask, request, abort, send_from_directory

BASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and make sure it stays inside BASE_DIR,
    # so "../" or absolute paths can't escape the files directory.
    requested = os.path.join(BASE_DIR, name)
    real = os.path.realpath(requested)
    if os.path.commonpath([real, BASE_DIR]) != BASE_DIR:
        abort(403, "forbidden")

    if not os.path.isfile(real):
        abort(404, "not found")

    return send_from_directory(BASE_DIR, os.path.basename(real))


if __name__ == "__main__":
    app.run()
