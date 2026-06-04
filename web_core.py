import logging
import os
import secrets
from datetime import timedelta

from flask import jsonify, request, session


STATUS_META = {
    "solicitado": {"label": "Pendente", "class": "warning text-dark", "icon": "hourglass-split"},
    "autorizado": {"label": "Autorizado", "class": "info text-dark", "icon": "check-circle"},
    "lancado": {"label": "Lançado", "class": "success", "icon": "check2-circle"},
    "indeferido": {"label": "Indeferido", "class": "danger", "icon": "x-circle"},
    "cancelado": {"label": "Cancelado", "class": "secondary", "icon": "slash-circle"},
    "estornado": {"label": "Estornado", "class": "secondary", "icon": "arrow-counterclockwise"},
    "ativo": {"label": "Ativo", "class": "success", "icon": "check-circle"},
    "inativo": {"label": "Inativo", "class": "secondary", "icon": "pause-circle"},
}


def configure_app_security(app):
    secret = os.environ.get("SECRET_KEY")
    if not secret:
        secret = secrets.token_hex(32)
        app.logger.warning("SECRET_KEY não configurada; usando chave temporária desta execução.")
    app.secret_key = secret
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production" or bool(os.environ.get("RENDER")),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_HOURS", "8"))),
    )


def ensure_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    expected = session.get("_csrf_token")
    supplied = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
    return bool(expected and supplied and secrets.compare_digest(str(expected), str(supplied)))


def apply_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net data:; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'",
    )
    if request.path.startswith(("/login", "/trocar-senha", "/recuperar-senha", "/meu-cadastro")):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def api_response(ok=True, message="", data=None, status=200, **extra):
    payload = {"ok": bool(ok), "message": message, "data": data}
    payload.update(extra)
    return jsonify(payload), status


def api_error(message, status=400, **extra):
    return api_response(False, message, status=status, erro=message, **extra)


def api_success(message="", data=None, status=200, **extra):
    return api_response(True, message, data=data, status=status, **extra)


def status_meta(value):
    key = str(value or "").lower()
    return STATUS_META.get(key, {"label": str(value or "-").title(), "class": "secondary", "icon": "circle"})


def configure_logging(app):
    if not app.logger.handlers:
        logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)
