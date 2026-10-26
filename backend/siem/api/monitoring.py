"""Host health and a demo login endpoint that records each attempt as an event."""

import random
import time

import psutil
from flask import Blueprint, jsonify, request

from ..auth import login_required
from ..db import get_db
from ..pipeline import ingest_items

bp = Blueprint("monitoring", __name__, url_prefix="/api")

DEMO_USERS = ["alice", "bob", "carol", "dave"]


@bp.get("/system-health")
@login_required
def system_health():
    try:
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        return jsonify({"cpu": cpu, "memory": mem, "disk": disk, "timestamp": time.strftime("%H:%M:%S")})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _record_login(user, success, latency_ms):
    ingest_items(get_db(), [{
        "source": "demo-api",
        "host": "demo-api",
        "category": "authentication",
        "action": "login",
        "outcome": "success" if success else "failure",
        "severity": "info" if success else "low",
        "user": user,
        "src_ip": request.remote_addr,
        "message": f"Demo API login {'succeeded' if success else 'failed'} for {user} ({latency_ms:.0f} ms)",
    }])


@bp.post("/demo/login")
@login_required
def simulate_login():
    """Simulated login target: adds random latency, fails 10% of the time and logs an event.

    Needs a signed-in analyst: on a public server, anyone could otherwise fill the database.
    """
    start_time = time.time()
    time.sleep(random.uniform(0.01, 0.2))
    body = request.get_json(silent=True)
    body = body if isinstance(body, dict) else {}
    user = str(body.get("user") or random.choice(DEMO_USERS))
    success = random.random() >= 0.1
    latency = (time.time() - start_time) * 1000

    _record_login(user, success, latency)
    if not success:
        return jsonify({"message": "Login Failed"}), 500
    return jsonify({"message": "Login Successful"}), 200
