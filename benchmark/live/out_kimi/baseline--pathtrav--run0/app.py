import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


@app.route("/download")
def download():
    path = os.path.join(FILES_DIR, request.args.get("name", ""))
    # ponytail: no traversal guard — rejects anything escaping FILES_DIR
    if not os.path.abspath(path).startswith(os.path.abspath(FILES_DIR) + os.sep):
        abort(403)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == "__main__":
    app.run()
