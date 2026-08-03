import os
from flask import Flask, request, send_file

app = Flask(__name__)

FILES_DIR = "./files"


@app.route("/download")
def download():
    name = request.args.get("name")
    path = os.path.join(FILES_DIR, name)
    return send_file(path)


if __name__ == "__main__":
    app.run()
