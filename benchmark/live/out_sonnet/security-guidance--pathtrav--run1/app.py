import os

from flask import Flask, request, send_from_directory

app = Flask(__name__)
FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files")


@app.route("/download")
def download():
    # send_from_directory (not os.path.join) blocks ../ path traversal.
    return send_from_directory(FILES_DIR, request.args.get("name", ""))


if __name__ == "__main__":
    app.run()
