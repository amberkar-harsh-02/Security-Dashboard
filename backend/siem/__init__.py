import logging
import os

from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from . import auth, blocks, db, detection, jobs, web
from .api import alerts as alerts_api
from .api import events as events_api
from .api import monitoring as monitoring_api
from .api import simulate as simulate_api
from .api import stats as stats_api
from .config import DEFAULT_INGEST_KEY, Config
from .performance import PerformanceMonitor

log = logging.getLogger("siem")


def create_app(config=None):
    config = config or Config()

    app = Flask(__name__)
    app.config["SIEM"] = config
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    app.json.sort_keys = False
    if config.TRUST_PROXY:
        # Real client address and scheme from the proxy, for login throttling and sign-in events.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    CORS(app, resources={r"/api/*": {"origins": config.CORS_ORIGINS}})

    db.init_schema(config.DB_PATH)
    blocks.configure(config)
    app.teardown_appcontext(db.close_db)

    # Invalid rule files stop startup with a message naming the file.
    engine = detection.Engine(config.RULES_DIR, config.INTEL_DIR)
    detection.configure(engine)
    app.extensions["siem_engine"] = engine
    app.extensions["siem_performance"] = PerformanceMonitor(config.PERF_INTERVAL)

    conn = db.connect(config.DB_PATH)
    try:
        auth.init_app(app, config, conn)
    finally:
        conn.close()

    app.register_blueprint(events_api.bp)
    app.register_blueprint(stats_api.bp)
    app.register_blueprint(monitoring_api.bp)
    app.register_blueprint(alerts_api.bp)
    if config.SIMULATOR_ENABLED:
        app.register_blueprint(simulate_api.bp)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok"})

    # Registered last so its catch-all route never shadows an API route.
    web.init_app(app, config.FRONTEND_DIST)

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify({"error": exc.description}), exc.code

    if config.INGEST_API_KEY == DEFAULT_INGEST_KEY:
        log.warning("Using the default ingest API key. Set SIEM_INGEST_KEY outside development.")

    # With the debug reloader, only the child process (WERKZEUG_RUN_MAIN) should run jobs,
    # otherwise two syslog listeners fight over the port.
    reloader_parent = config.DEBUG and os.environ.get("WERKZEUG_RUN_MAIN") != "true"
    if config.START_BACKGROUND_JOBS and not reloader_parent:
        app.extensions["siem_jobs"] = jobs.start(config, app.extensions["siem_performance"])

    return app
