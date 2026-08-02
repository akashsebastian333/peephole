from flask import Flask, request, send_from_directory
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return 'Missing name parameter', 400

    # ponytail: basename prevents path traversal; send_from_directory validates bounds
    safe_name = os.path.basename(name)
    return send_from_directory('./files', safe_name)

if __name__ == '__main__':
    app.run(debug=False)
