from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)
FILES_DIR = "files"


@app.route("/download")
def download():
    name = request.args.get("name")
    if not name:
        abort(400)
    try:
        return send_from_directory(FILES_DIR, name)
    except Exception:
        abort(404)


if __name__ == "__main__":
    app.run()
