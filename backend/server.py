from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import time

app = Flask(__name__)
CORS(app)

@app.route('/api/system-health', methods=['GET'])
def system_health():
    try:
        cpu_usage = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        return jsonify({
            "cpu": cpu_usage,
            "memory": memory.percent,
            "disk": disk.percent,
            "timestamp": time.strftime("%H:%M:%S")
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("Starting SIEM Backend on port 5000...")
    app.run(debug=True, port=5000)