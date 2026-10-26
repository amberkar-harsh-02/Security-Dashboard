from flask import Blueprint, current_app, jsonify

from .. import simulator
from ..auth import check_session

bp = Blueprint("simulate", __name__, url_prefix="/api/simulate")
bp.before_request(check_session)


@bp.get("")
def list_scenarios():
    return jsonify({"scenarios": simulator.list_scenarios()})


@bp.post("/<name>")
def run_scenario(name):
    try:
        ids = simulator.run_scenario(current_app.config["SIEM"].DB_PATH, name)
    except KeyError:
        known = ", ".join(simulator.SCENARIOS)
        return jsonify({"error": f"Unknown scenario {name!r}. Use one of: {known}"}), 404
    return jsonify({"scenario": name, "events": len(ids)}), 201
