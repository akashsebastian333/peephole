from flask import Flask, request, send_from_directory

app = Flask(__name__)
FILES_DIR = "files"


@app.route("/download")
def download():
    name = request.args.get("name", "")
    return send_from_directory(FILES_DIR, name)


if __name__ == "__main__":
    app.run()
