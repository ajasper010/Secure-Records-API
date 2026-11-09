import logging

from flask import Flask, jsonify
from werkzeug.exceptions import HTTPException

from . import db
from .config import build_config
from .routes import bp
from .validation import Forbidden, ValidationError


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.update(build_config(overrides))
    db.init_db(app)
    app.teardown_appcontext(db.close_db)
    app.register_blueprint(bp)

    @app.errorhandler(ValidationError)
    def _bad_request(e):
        return jsonify(error=str(e)), 400

    @app.errorhandler(Forbidden)
    def _forbidden(e):
        return jsonify(error=str(e)), 403

    @app.errorhandler(HTTPException)
    def _http(e):
        # Oversized body (413) is reported as a clean 400 per the spec; everything else keeps its code.
        code = 400 if e.code == 413 else e.code
        return jsonify(error=e.name if code != 400 else "bad request"), code

    @app.errorhandler(Exception)
    def _unhandled(e):
        app.logger.exception("unhandled error")  # details stay in server logs only
        return jsonify(error="internal server error"), 500

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    return app
