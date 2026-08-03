import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
FILES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "files"))


@app.route("/download")
def download():
    path = os.path.abspath(os.path.join(FILES_DIR, request.args.get("name", "")))
    if not path.startswith(FILES_DIR + os.sep):
        abort(403)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == "__main__":
    app.run(debug=False)
