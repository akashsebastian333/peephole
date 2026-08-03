import os
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.realpath("files")


@app.route("/download")
def download():
    name = request.args.get("name", "")
    # ponytail: send_from_directory rejects '..'/absolute paths itself; no extra sanitizing needed
    if not name or os.path.isabs(name):
        abort(400)
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run()
