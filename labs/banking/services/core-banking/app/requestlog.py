"""Structured per-request application logging for the banking services.

Each service's nginx already writes an access/error log (proxy-layer
evidence). This adds the *application* layer: one structured JSON line per
request as Flask actually saw it -- a traceable request_id, the method/url,
query params, headers and body -- so the defender can correlate what the app
processed with what nginx and the network IDS saw.

Output goes to APP_LOG_PATH (default /var/log/nginx/application.log), which
each service already bind-mounts to labs/banking/logs/<service>/, so Filebeat
ships it with no extra container volume. Lines are JSON, one per request, with
log_type=application so the banking-application-* index/pipeline/data-view pick
them up.

PII policy: only password material is redacted (per the lab's logging policy),
plus the Authorization header since HTTP Basic carries the password inline.
Everything else is captured verbatim for full defender visibility.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from flask import g, request

# Any field (query/form/json key) whose name contains one of these is
# redacted. Kept deliberately narrow: the only in-scope PII is the password.
_REDACT_SUBSTRINGS = ("password", "passwd", "pwd")
_REDACT_HEADERS = {"authorization"}  # Basic-auth carries the password inline
_REDACTED = "***REDACTED***"


def _redact_mapping(mapping):
    out = {}
    for key, value in mapping.items():
        lk = str(key).lower()
        if any(s in lk for s in _REDACT_SUBSTRINGS):
            out[key] = _REDACTED
        else:
            out[key] = value
    return out


def _redact_headers(headers):
    out = {}
    for key, value in headers.items():
        out[key] = _REDACTED if key.lower() in _REDACT_HEADERS else value
    return out


def _request_body():
    """Best-effort structured body. Reads Flask's cached form/json (safe in
    after_request -- the view has already parsed it), never re-consuming the
    stream. Always returns an object so the ES `flattened` mapping accepts it."""
    ctype = (request.content_type or "").lower()
    if request.form:
        return _redact_mapping(request.form.to_dict(flat=True))
    if "application/json" in ctype:
        parsed = request.get_json(silent=True)
        if isinstance(parsed, dict):
            return _redact_mapping(parsed)
        if parsed is not None:
            return {"_json": parsed}
    raw = request.get_data(cache=True, as_text=True) or ""
    if raw:
        return {"_raw": raw[:4096]}
    return {}


def init_request_logging(app, service_name):
    logger = logging.getLogger("banking.request.%s" % service_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        log_path = os.environ.get("APP_LOG_PATH", "/var/log/nginx/application.log")
        handler = RotatingFileHandler(log_path, maxBytes=10_000_000, backupCount=3)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

    def _emit(status, error=None):
        try:
            start = getattr(g, "_req_start", None)
            duration_ms = round((time.perf_counter() - start) * 1000, 2) if start else None
            record = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "service": service_name,
                "log_type": "application",
                "request_id": getattr(g, "_request_id", ""),
                "method": request.method,
                "url": request.url,
                "path": request.path,
                "query": _redact_mapping(request.args.to_dict(flat=True)),
                "headers": _redact_headers(dict(request.headers)),
                "body": _request_body(),
                "remote_addr": request.remote_addr,
                "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
                "user_agent": request.headers.get("User-Agent", ""),
                "status": status,
                "duration_ms": duration_ms,
            }
            if error:
                # Object form (error.message) matches the banking-application
                # template and Filebeat's own add_error_key convention -- a bare
                # string here would collide with that object mapping in ES.
                record["error"] = {"message": error}
            logger.info(json.dumps(record, default=str))
        except Exception:  # logging must never break the request path
            pass

    @app.before_request
    def _start_timer():
        g._req_start = time.perf_counter()
        g._request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex

    @app.after_request
    def _log_response(response):
        _emit(response.status_code)
        g._logged = True
        response.headers["X-Request-ID"] = getattr(g, "_request_id", "")
        return response

    @app.teardown_request
    def _log_teardown(exc):
        # after_request is skipped when an unhandled exception propagates;
        # catch that case here so a 500 still produces exactly one app log line.
        if getattr(g, "_logged", False):
            return
        _emit(500 if exc else 0, error=str(exc) if exc else None)
