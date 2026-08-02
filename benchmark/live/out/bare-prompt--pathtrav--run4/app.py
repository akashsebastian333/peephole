from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        return {'error': 'name parameter required'}, 400

    filepath = os.path.join('./files', os.path.basename(name))

    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return {'error': 'File not found'}, 404

    return send_file(filepath)

if __name__ == '__main__':
    app.run()
