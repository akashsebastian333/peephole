from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return 'No file specified', 400

    file_path = os.path.join('./files', name)

    try:
        return send_file(file_path)
    except FileNotFoundError:
        return 'File not found', 404

if __name__ == '__main__':
    app.run(debug=True)
