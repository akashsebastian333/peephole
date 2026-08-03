from flask import Flask, request, send_from_directory, abort

app = Flask(__name__)


@app.route("/download")
def download():
    name = request.args.get("name", "")
    if not name:
        abort(400)
    return send_from_directory("files", name)


if __name__ == "__main__":
    app.run()
