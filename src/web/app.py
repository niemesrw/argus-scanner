"""
Flask web application for Argus Scanner dashboard
"""

import logging
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from datetime import datetime, timedelta

from src.config.settings import Settings
from src.database.models import (
    Device,
    Service,
    Vulnerability,
    Alert,
    Scan,
    get_db_session,
    Severity,
)
from src.web.routes import api_bp, dashboard_bp

logger = logging.getLogger(__name__)


def create_app(settings: Settings) -> Flask:
    """Create and configure Flask application"""
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # Configuration
    app.config["SECRET_KEY"] = settings.secret_key
    app.config["JSON_SORT_KEYS"] = False

    # Enable CORS for API endpoints
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Store settings in app config
    app.config["SETTINGS"] = settings
    app.config["DB_PATH"] = settings.db_path

    # Register blueprints
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(dashboard_bp)

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found"}), 404
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal error: {error}")
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("500.html"), 500

    # Health check endpoint
    @app.route("/health")
    def health_check():
        try:
            db = get_db_session(settings.db_path)
            device_count = db.query(Device).count()
            db.close()

            return jsonify(
                {
                    "status": "healthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "environment": settings.environment,
                    "device_count": device_count,
                }
            )
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({"status": "unhealthy", "error": str(e)}), 503

    # Dashboard context processor
    @app.context_processor
    def inject_globals():
        return {
            "app_name": "Argus Scanner",
            "environment": settings.environment,
            "now": datetime.utcnow(),
        }

    return app
