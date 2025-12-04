from flask import Flask, jsonify, request
from flask_cors import CORS
import psutil
import time
import random

app = Flask(__name__)
CORS(app)

# --- GLOBAL STORAGE FOR API STATS ---
api_stats = {
    "status": "Healthy",
    "total_requests": 0,
    "failed_requests": 0,
    "avg_latency": 0
}

# --- ROUTES ---

@app.route('/api/system-health', methods=['GET'])
def system_health():
    try:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        return jsonify({"cpu": cpu, "memory": mem, "disk": disk, "timestamp": time.strftime("%H:%M:%S")})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/login', methods=['POST'])
def simulate_login():
    """ 
    Simulates a user login. Randomly fails or lags to create 'interesting' data.
    """
    global api_stats
    start_time = time.time()

    # Simulate network lag (10ms to 200ms)
    time.sleep(random.uniform(0.01, 0.2))

    api_stats["total_requests"] += 1

    # 10% chance to fail (500 Error)
    if random.random() < 0.1:
        api_stats["failed_requests"] += 1
        api_stats["status"] = "Degraded" if api_stats["failed_requests"] > 5 else "Healthy"
        return jsonify({"message": "Login Failed"}), 500

    # Calculate latency
    latency = (time.time() - start_time) * 1000
    # Update average (weighted average)
    api_stats["avg_latency"] = (api_stats["avg_latency"] * 0.9) + (latency * 0.1)

    return jsonify({"message": "Login Successful"}), 200

@app.route('/api/monitor-stats', methods=['GET'])
def get_monitor_stats():
    """ React calls this to get the current API stats """
    return jsonify(api_stats)

if __name__ == '__main__':
    print("Starting SIEM Backend on port 5000...")
    app.run(debug=True, port=5000)