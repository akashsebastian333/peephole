import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/ping', methods=['GET'])
def ping():
    host = request.args.get('host')
    if not host:
        return jsonify({'error': 'host required'}), 400

    try:
        result = subprocess.run(['ping', '-c', '1', host], capture_output=True, timeout=5, check=False)
        return jsonify({'status': 'success' if result.returncode == 0 else 'failed'})
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'timeout'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run()
