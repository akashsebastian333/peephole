import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Resolve the requested path and ensure it stays inside BASE_DIR
    # so that values like "../etc/passwd" cannot escape the files directory.
    target = os.path.abspath(os.path.join(BASE_DIR, name))
    if os.path.commonpath([BASE_DIR, target]) != BASE_DIR or target == BASE_DIR:
        abort(404)

    if not os.path.isfile(target):
        abort(404)

    return send_from_directory(BASE_DIR, os.path.relpath(target, BASE_DIR))


if __name__ == "__main__":
    app.run()
