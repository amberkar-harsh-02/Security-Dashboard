"""Serve the built dashboard (frontend/dist) from Flask, and set security headers.

With a build present, the whole SIEM runs on one port. In development the Vite dev
server on port 3000 serves the dashboard instead and forwards /api here.
"""

from pathlib import Path

from flask import abort, jsonify, request, send_from_directory

# The dashboard loads only its own files and talks only to this server.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    # React sets a few style attributes (chart widths, meters); stylesheets are files.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    if response.mimetype == "text/html":
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    return response


def init_app(app, dist_dir):
    dist = Path(dist_dir)
    app.after_request(add_security_headers)

    @app.get("/")
    @app.get("/<path:path>")
    def dashboard(path=""):
        # Unknown API paths stay JSON errors, never the dashboard page.
        if path == "api" or path.startswith("api/"):
            abort(404)
        if not (dist / "index.html").is_file():
            return jsonify({
                "message": "The dashboard is not built. Run `npm run build` in frontend/, "
                "or use `npm run dev` there and open http://localhost:3000.",
            }), 404

        file = dist / path
        if path and file.is_file() and file.resolve().is_relative_to(dist.resolve()):
            response = send_from_directory(dist, path)
            # Vite puts a content hash in asset names, so they never change.
            if path.startswith("assets/"):
                response.cache_control.max_age = 31536000
                response.cache_control.immutable = True
            return response

        # Any other path is a dashboard route (/alerts/12, /events?...): serve the app shell.
        if "." in Path(path).name and request.accept_mimetypes.best != "text/html":
            abort(404)
        response = send_from_directory(dist, "index.html")
        response.cache_control.no_cache = True
        return response
