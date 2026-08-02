import os

from flask import Flask, request, send_from_directory

app = Flask(__name__)

FILES_DIR = os.path.abspath("./files")


@app.route("/download")
def download():
    # basename strips any directory components, so ../../etc/passwd can't escape FILES_DIR.
    name = os.path.basename(request.args.get("name", ""))
    if not name:
        return "not found", 404
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
