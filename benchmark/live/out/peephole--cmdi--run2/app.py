from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return jsonify({'error': 'host parameter required'}), 400

    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, timeout=5)
        return jsonify({'status': 'success' if result.returncode == 0 else 'failed'})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'timeout'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', debug=os.environ.get('FLASK_DEBUG') == '1')
