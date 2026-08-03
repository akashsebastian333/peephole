import os

from flask import Flask, abort, request, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400)
    # send_from_directory resolves 'name' against FILES_DIR and 404s on any
    # path that escapes it (traversal, absolute paths, symlink escapes).
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run()
