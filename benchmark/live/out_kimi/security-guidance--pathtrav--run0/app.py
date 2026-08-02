import os

from flask import Flask, abort, request, send_file

app = Flask(__name__)
FILES_DIR = os.path.abspath("./files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.realpath(os.path.join(FILES_DIR, name))
    if os.path.commonpath((FILES_DIR, path)) != FILES_DIR:
        abort(400)
    return send_file(path)


if __name__ == "__main__":
    app.run()
