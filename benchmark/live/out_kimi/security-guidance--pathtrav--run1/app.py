import os
from flask import Flask, abort, request, send_file

app = Flask(__name__)
FILES_DIR = os.path.abspath("./files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    path = os.path.abspath(os.path.join(FILES_DIR, name))
    if not (path == FILES_DIR or path.startswith(FILES_DIR + os.sep)) or not os.path.isfile(path):
        abort(404)
    return send_file(path)


if __name__ == "__main__":
    app.run()
