# """
# Flask API for Web Based Security Analyzer
# """

# import os
# import sys
# import logging
# from flask import Flask, request, jsonify, send_from_directory
# from flask_cors import CORS
# import requests

# app = Flask(__name__, static_folder="../frontend")
# CORS(app)

# # Home route
# @app.route("/")
# def home():
#     return send_from_directory("../frontend", "index.html")

# # -----------------------------
# # logging
# # -----------------------------
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # -----------------------------
# # setup paths
# # -----------------------------
# _BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))

# if _BACKEND_DIR not in sys.path:
#     sys.path.insert(0, _BACKEND_DIR)

# _PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
# _FRONTEND_DIR = os.path.join(_PROJECT_ROOT, "frontend")
# _REPORTS_DIR = os.path.join(_PROJECT_ROOT, "reports")

# # -----------------------------
# # flask app
# # -----------------------------
# app = Flask(__name__, static_folder=_FRONTEND_DIR, static_url_path="")
# CORS(app)

# # -----------------------------
# # import scanner modules
# # -----------------------------
# try:
#     from scanner_controller import run_scan
# except ImportError:
#     logger.warning("scanner_controller module not found.")
#     run_scan = None

# try:
#     from pdf_report import write_pdf_report
# except ImportError:
#     logger.warning("pdf_report module not found.")
#     write_pdf_report = None

# # -----------------------------
# # FRONTEND ROUTES
# # -----------------------------

# @app.route("/")
# def index():
#     return send_from_directory(_FRONTEND_DIR, "index.html")


# @app.route("/scan.html")
# def scan_page():
#     return send_from_directory(_FRONTEND_DIR, "scan.html")


# @app.route("/dashboard.html")
# def dashboard_page():
#     return send_from_directory(_FRONTEND_DIR, "dashboard.html")


# @app.route("/script.js")
# def serve_script():
#     return send_from_directory(_FRONTEND_DIR, "script.js")


# @app.route("/style.css")
# def serve_style():
#     return send_from_directory(_FRONTEND_DIR, "style.css")


# @app.route("/reports/<path:name>")
# def serve_report(name):
#     return send_from_directory(_REPORTS_DIR, name, as_attachment=True)


# # -----------------------------
# # SCAN API
# # -----------------------------

# @app.route("/scan", methods=["GET", "POST"])
# def scan():

#     try:

#         # -------------------------
#         # Get URL from request
#         # -------------------------
#         if request.method == "GET":
#             url = request.args.get("url")
#         else:
#             data = request.get_json()
#             url = data.get("url") if data else None

#         if not url:
#             return jsonify({"error": "Missing URL"}), 400

#         logger.info(f"Starting scan for: {url}")

#         if run_scan is None:
#             return jsonify({
#                 "error": "Scanner engine not available"
#             }), 500

#         # -------------------------
#         # Run scan
#         # -------------------------
#         result = run_scan(url)

#         pdf_rel = None

#         # -------------------------
#         # Generate PDF report
#         # -------------------------
#         if write_pdf_report:
#             try:

#                 os.makedirs(_REPORTS_DIR, exist_ok=True)

#                 pdf_path = write_pdf_report(
#                     _REPORTS_DIR,
#                     result["scan_id"],
#                     url,
#                     result["summary"]["score"],
#                     result["summary"]["risk"],
#                     result["vulnerabilities"],
#                     result.get("details"),
#                 )

#                 pdf_rel = os.path.basename(pdf_path)

#             except Exception as e:
#                 logger.error("PDF generation failed")
#                 logger.exception(e)

#         # -------------------------
#         # Build response
#         # -------------------------
#         response = {
#             "scan_id": result.get("scan_id"),
#             "target": result.get("target"),
#             "summary": result.get("summary"),
#             "vulnerabilities": result.get("vulnerabilities"),
#             "findings_by_category": result.get("findings_by_category"),
#             "modules": result.get("modules"),
#             "details": result.get("details"),
#             "score": result["summary"]["score"],
#             "risk": result["summary"]["risk"],
#         }

#         if pdf_rel:
#             response["pdf_report"] = f"/reports/{pdf_rel}"

#         return jsonify(response)

#     except Exception as e:

#         logger.exception("Scan failed")

#         return jsonify({
#             "error": "Scan failed",
#             "message": str(e)
#         }), 500


# # -----------------------------
# # HEALTH CHECK
# # -----------------------------

# @app.route("/api/health")
# def health():
#     return jsonify({
#         "status": "ok",
#         "service": "web-security-analyzer"
#     })


# # -----------------------------
# # RUN SERVER
# # -----------------------------

# if __name__ == "__main__":

#     os.makedirs(_REPORTS_DIR, exist_ok=True)

#     logger.info("Starting Web Security Analyzer API...")

#     app.run(
#         host="0.0.0.0",
#         port=5000,
#         debug=True
#     )





















from flask import Flask, request, jsonify
from flask_cors import CORS
import uuid
import traceback
from scanner_controller import run_scan

app = Flask(__name__)

# Allow all localhost origins (works for any port during development)
CORS(app, resources={r"/*": {"origins": ["http://localhost:*", "http://127.0.0.1:*", "null"]}})


def error_response(message, status=400):
    """Always return valid JSON on errors — never let Flask return HTML."""
    return jsonify({
        "success": False,
        "error": message,
        "scan_id": None,
        "target": None,
        "summary": {"score": 0, "risk": "UNKNOWN"},
        "vulnerabilities": [],
        "modules": [],
        "details": {}
    }), status


@app.errorhandler(404)
def not_found(e):
    return error_response("Endpoint not found. Use POST /scan", 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return error_response("Method not allowed. Use POST /scan", 405)


@app.errorhandler(500)
def internal_error(e):
    return error_response("Internal server error", 500)


@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "message": "Security Analyzer API is running. POST to /scan"})


@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(silent=True)

        if not data:
            return error_response("Request body must be JSON with a 'url' field.")

        target_url = data.get("url", "").strip()

        if not target_url:
            return error_response("Missing 'url' in request body.")

        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        scan_id = str(uuid.uuid4())[:8]
        result = run_scan(target_url, scan_id)

        return jsonify(result), 200

    except Exception as e:
        traceback.print_exc()
        return error_response(f"Scan failed: {str(e)}", 500)


if __name__ == "__main__":
    app.run(debug=True, port=5000)