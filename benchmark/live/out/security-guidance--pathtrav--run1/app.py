from flask import Flask, send_file, request, abort
import os

app = Flask(__name__)

@app.route('/download')
def download():
    name = request.args.get('name')
    if not name:
        abort(400)

    filepath = os.path.join('./files', name)

    try:
        return send_file(filepath, as_attachment=True)
    except FileNotFoundError:
        abort(404)
    except Exception as e:
        abort(500)

if __name__ == '__main__':
    app.run(debug=True)
