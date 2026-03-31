# """
# Scanner controller: orchestrates all vulnerability modules and aggregates results.

# Flow:
# 1. URL analysis (reachability, HTTPS after redirects)
# 2. Security headers (from successful page fetch)
# 3. Optional same-host link crawl
# 4. TCP port scan on target host
# 5. Reflected XSS probe
# 6. SQL error-pattern probe
# 7. SSL/TLS certificate check

# Only use against systems you are authorized to test.
# """

# from __future__ import annotations

# import uuid
# from urllib.parse import urlparse

# import requests

# from headers_check import check_security_headers
# from port_scan import scan_common_ports
# from scoring import compute_score
# from sql_scan import test_sql_injection
# from ssl_check import check_ssl_certificate
# from url_analyzer import crawl_internal_links, validate_and_fetch
# from xss_scan import test_reflected_xss

# STANDARD_WEB_PORTS = {80, 443}


# def _dedupe_preserve_order(items: list[str]) -> list[str]:
#     return list(dict.fromkeys(items))


# def _findings_by_category(
#     url_vulns: list[str],
#     header_vulns: list[str],
#     port_vulns: list[str],
#     xss_vulns: list[str],
#     sqli_vulns: list[str],
#     ssl_vulns: list[str],
# ) -> dict[str, list[str]]:
#     return {
#         "url": list(url_vulns),
#         "headers": list(header_vulns),
#         "ports": list(port_vulns),
#         "xss": list(xss_vulns),
#         "sqli": list(sqli_vulns),
#         "ssl": list(ssl_vulns),
#     }


# def run_scan(url: str) -> dict:
#     """
#     Execute all scanner modules and return a structured result dict for the API.

#     Returns:
#         scan_id, summary (score, risk, counts), flat vulnerabilities list,
#         modules (per-module payloads), findings_by_category, and legacy-shaped
#         `details` for older clients (same as modules).
#     """
#     scan_id = str(uuid.uuid4())
#     all_vulns: list[str] = []

#     # --- Phase 1: URL reachability & transport (redirects, HTTPS) ---
#     url_info = validate_and_fetch(url)
#     url_vulns = list(url_info.get("vulnerabilities", []))
#     all_vulns.extend(url_vulns)

#     modules: dict = {
#         "url_analysis": url_info,
#         "headers": None,
#         "ports": None,
#         "xss": None,
#         "sqli": None,
#         "ssl": None,
#         "crawler": None,
#     }

#     if not url_info["valid"]:
#         unique = _dedupe_preserve_order(all_vulns)
#         score, risk = compute_score(unique)
#         if any("Invalid URL" in v for v in unique):
#             score = 0
#             risk = "High"
#         return _build_response(
#             scan_id=scan_id,
#             original_url=url.strip(),
#             score=score,
#             risk=risk,
#             vulnerabilities=unique,
#             modules=modules,
#             url_vulns=url_vulns,
#             header_vulns=[],
#             port_vulns=[],
#             xss_vulns=[],
#             sqli_vulns=[],
#             ssl_vulns=[],
#         )

#     fetch_url = url_info.get("final_url") or url.strip()
#     html_snippet = ""

#     # --- Phase 2: Response headers (CSP, frame options, HSTS, etc.) ---
#     try:
#         r = requests.get(
#             fetch_url,
#             timeout=15,
#             headers={"User-Agent": "WebSecurityAnalyzer/1.0"},
#             verify=True,
#         )
#         headers_result = check_security_headers(dict(r.headers))
#         modules["headers"] = headers_result
#         all_vulns.extend(headers_result.get("vulnerabilities", []))
#         html_snippet = r.text or ""
#         modules["http_status"] = r.status_code
#     except requests.RequestException as e:
#         modules["headers_error"] = str(e)

#     header_vulns = list(modules["headers"].get("vulnerabilities", [])) if modules.get("headers") else []

#     # --- Phase 3: Same-host link discovery (attack surface hints) ---
#     if html_snippet:
#         modules["crawler"] = crawl_internal_links(fetch_url, html_snippet)

#     parsed = urlparse(fetch_url)
#     host = parsed.hostname
#     port_vulns: list[str] = []
#     # --- Phase 4: TCP ports (non-80/443 openings reported as findings) ---
#     if host:
#         ports = scan_common_ports(host)
#         modules["ports"] = ports
#         for p in ports.get("open_ports", []):
#             if p not in STANDARD_WEB_PORTS:
#                 label = f"Open port {p}"
#                 all_vulns.append(label)
#                 port_vulns.append(label)
#         if ports.get("error"):
#             modules["ports"]["warning"] = ports["error"]

#     # --- Phase 5: Reflected XSS probe ---
#     xss = test_reflected_xss(fetch_url)
#     modules["xss"] = xss
#     xss_vulns = list(xss.get("vulnerabilities", []))
#     all_vulns.extend(xss_vulns)

#     # --- Phase 6: SQL error-pattern probe ---
#     sqli = test_sql_injection(fetch_url)
#     modules["sqli"] = sqli
#     sqli_vulns = list(sqli.get("vulnerabilities", []))
#     all_vulns.extend(sqli_vulns)

#     # --- Phase 7: TLS certificate & HTTPS-only checks ---
#     ssl_info = check_ssl_certificate(fetch_url)
#     modules["ssl"] = ssl_info
#     ssl_vulns = list(ssl_info.get("vulnerabilities", []))
#     all_vulns.extend(ssl_vulns)

#     unique = _dedupe_preserve_order(all_vulns)
#     score, risk = compute_score(unique)

#     return _build_response(
#         scan_id=scan_id,
#         original_url=url.strip(),
#         score=score,
#         risk=risk,
#         vulnerabilities=unique,
#         modules=modules,
#         url_vulns=url_vulns,
#         header_vulns=header_vulns,
#         port_vulns=port_vulns,
#         xss_vulns=xss_vulns,
#         sqli_vulns=sqli_vulns,
#         ssl_vulns=ssl_vulns,
#     )


# def _build_response(
#     scan_id: str,
#     original_url: str,
#     score: int,
#     risk: str,
#     vulnerabilities: list[str],
#     modules: dict,
#     url_vulns: list[str],
#     header_vulns: list[str],
#     port_vulns: list[str],
#     xss_vulns: list[str],
#     sqli_vulns: list[str],
#     ssl_vulns: list[str],
# ) -> dict:
#     findings = _findings_by_category(
#         url_vulns, header_vulns, port_vulns, xss_vulns, sqli_vulns, ssl_vulns
#     )
#     modules_out = {**modules, "scan_id": scan_id}
#     return {
#         "scan_id": scan_id,
#         "target": {
#             "url": original_url,
#             "final_url": (modules.get("url_analysis") or {}).get("final_url"),
#             "valid": (modules.get("url_analysis") or {}).get("valid", False),
#         },
#         "summary": {
#             "score": score,
#             "risk": risk,
#             "total_findings": len(vulnerabilities),
#             "modules_executed": [
#                 "url_analysis",
#                 "headers",
#                 "crawler",
#                 "ports",
#                 "xss",
#                 "sqli",
#                 "ssl",
#             ],
#         },
#         "vulnerabilities": vulnerabilities,
#         "findings_by_category": findings,
#         "modules": modules_out,
#         # Same payload as legacy `details` for PDF / older clients
#         "details": modules_out,
#     }





import requests
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections (HSTS)",
        "severity": "HIGH"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and data injection attacks",
        "severity": "HIGH"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "severity": "MEDIUM"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "severity": "MEDIUM"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent with requests",
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "severity": "LOW"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (older browsers)",
        "severity": "LOW"
    }
}


def check_https(url):
    """Check if the site uses HTTPS and if the SSL cert is valid."""
    result = {
        "uses_https": url.startswith("https://"),
        "ssl_valid": False,
        "ssl_error": None
    }
    if result["uses_https"]:
        try:
            hostname = urlparse(url).hostname
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
            result["ssl_valid"] = True
        except Exception as e:
            result["ssl_error"] = str(e)
    return result


def check_security_headers(headers):
    """Check which security headers are present or missing."""
    present = []
    missing = []

    for header, info in SECURITY_HEADERS.items():
        if header.lower() in {k.lower() for k in headers.keys()}:
            present.append({
                "header": header,
                "value": headers.get(header, ""),
                "description": info["description"],
                "status": "PRESENT"
            })
        else:
            missing.append({
                "header": header,
                "description": info["description"],
                "severity": info["severity"],
                "status": "MISSING"
            })

    return present, missing


def check_server_info(headers):
    """Check for information disclosure via Server/X-Powered-By headers."""
    leaks = []
    for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
        if h in headers:
            leaks.append({
                "header": h,
                "value": headers[h],
                "risk": "Reveals server/technology info to attackers"
            })
    return leaks


def calculate_score(https_result, missing_headers, info_leaks):
    """Calculate a simple security score out of 100."""
    score = 100

    if not https_result["uses_https"]:
        score -= 30
    elif not https_result["ssl_valid"]:
        score -= 15

    for h in missing_headers:
        if h["severity"] == "HIGH":
            score -= 10
        elif h["severity"] == "MEDIUM":
            score -= 5
        else:
            score -= 2

    score -= len(info_leaks) * 3

    score = max(0, min(100, score))

    if score >= 80:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return score, risk


def run_scan(url, scan_id):
    """Main scan function. Returns a consistent JSON-serializable dict."""
    vulnerabilities = []
    modules = []

    # --- Fetch the page ---
    try:
        response = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "SecurityAnalyzer/1.0 (College Project)"})
        status_code = response.status_code
        headers = dict(response.headers)
        fetch_error = None
    except requests.exceptions.SSLError as e:
        return _error_scan(scan_id, url, f"SSL Error: {str(e)}")
    except requests.exceptions.ConnectionError as e:
        return _error_scan(scan_id, url, f"Connection failed: {str(e)}")
    except requests.exceptions.Timeout:
        return _error_scan(scan_id, url, "Request timed out after 10 seconds")
    except Exception as e:
        return _error_scan(scan_id, url, str(e))

    # --- Run checks ---
    https_result = check_https(url)
    present_headers, missing_headers = check_security_headers(headers)
    info_leaks = check_server_info(headers)
    score, risk = calculate_score(https_result, missing_headers, info_leaks)

    # --- Build vulnerabilities list ---
    if not https_result["uses_https"]:
        vulnerabilities.append({
            "id": "V001",
            "name": "No HTTPS",
            "severity": "HIGH",
            "description": "Site does not use HTTPS. Data is transmitted in plaintext.",
            "recommendation": "Install an SSL certificate and redirect HTTP to HTTPS."
        })

    if https_result["uses_https"] and not https_result["ssl_valid"]:
        vulnerabilities.append({
            "id": "V002",
            "name": "Invalid SSL Certificate",
            "severity": "HIGH",
            "description": f"SSL certificate error: {https_result.get('ssl_error')}",
            "recommendation": "Renew or fix your SSL certificate."
        })

    for h in missing_headers:
        vulnerabilities.append({
            "id": f"V-HDR-{h['header'].replace('-', '')}",
            "name": f"Missing {h['header']}",
            "severity": h["severity"],
            "description": h["description"],
            "recommendation": f"Add the '{h['header']}' HTTP response header."
        })

    for leak in info_leaks:
        vulnerabilities.append({
            "id": f"V-LEAK-{leak['header']}",
            "name": f"Information Disclosure: {leak['header']}",
            "severity": "LOW",
            "description": leak["risk"],
            "recommendation": f"Remove or obscure the '{leak['header']}' header."
        })

    # --- Build modules summary ---
    modules = [
        {"name": "HTTPS Check", "status": "PASS" if https_result["uses_https"] else "FAIL",
         "findings": 0 if https_result["uses_https"] else 1},
        {"name": "Security Headers", "status": "PASS" if not missing_headers else "WARN",
         "findings": len(missing_headers)},
        {"name": "Information Disclosure", "status": "PASS" if not info_leaks else "WARN",
         "findings": len(info_leaks)},
    ]

    return {
        "success": True,
        "scan_id": scan_id,
        "target": url,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "http_status": status_code,
        "summary": {
            "score": score,
            "risk": risk,
            "total_vulnerabilities": len(vulnerabilities),
            "high": sum(1 for v in vulnerabilities if v["severity"] == "HIGH"),
            "medium": sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM"),
            "low": sum(1 for v in vulnerabilities if v["severity"] == "LOW"),
        },
        "vulnerabilities": vulnerabilities,
        "modules": modules,
        "details": {
            "https": https_result,
            "headers_present": present_headers,
            "headers_missing": missing_headers,
            "info_leaks": info_leaks,
            "response_headers": headers
        }
    }


def _error_scan(scan_id, url, error_msg):
    """Return a valid JSON structure even when the scan itself fails."""
    return {
        "success": False,
        "scan_id": scan_id,
        "target": url,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "error": error_msg,
        "summary": {"score": 0, "risk": "UNKNOWN", "total_vulnerabilities": 0,
                    "high": 0, "medium": 0, "low": 0},
        "vulnerabilities": [],
        "modules": [],
        "details": {}
    }