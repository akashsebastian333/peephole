from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400, "Missing 'name' parameter")

    filename = os.path.basename(name)
    filepath = os.path.join('./files', filename)

    if not os.path.exists(filepath):
        abort(404)

    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=False)
