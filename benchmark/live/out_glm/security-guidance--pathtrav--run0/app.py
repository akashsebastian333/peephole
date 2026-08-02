import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)

BASE_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400, "missing 'name' parameter")

    # Build the candidate path with os.path.join, then resolve it so that any
    # traversal segments (../) are collapsed. Reject anything that escapes
    # BASE_DIR — otherwise a caller could read arbitrary files on disk.
    candidate = os.path.realpath(os.path.join(BASE_DIR, name))

    if not candidate.startswith(BASE_DIR + os.sep):
        abort(403, "access denied")

    if not os.path.isfile(candidate):
        abort(404, "not found")

    return send_from_directory(BASE_DIR, os.path.relpath(candidate, BASE_DIR))


if __name__ == "__main__":
    app.run()
