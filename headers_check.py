"""
Security HTTP headers scanner.

Checks for headers that reduce common web risks:
- Content-Security-Policy (CSP): limits script/style/load sources (XSS, injection).
- X-Frame-Options: mitigates clickjacking by controlling framing.
- Strict-Transport-Security (HSTS): forces HTTPS for a period.
- X-XSS-Protection: legacy XSS filter hint in older browsers (legacy; still flagged if absent).

Missing headers are reported as findings; presence is checked case-insensitively.
"""

from __future__ import annotations

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection",
]


def check_security_headers(response_headers: dict) -> dict:
    """
    Compare response headers (case-insensitive keys) against ``REQUIRED_HEADERS``.

    Returns:
        present: map of header name -> bool
        missing: list of missing canonical header names
        vulnerabilities: human-readable strings for API aggregation
    """
    normalized = {k.lower(): v for k, v in response_headers.items()}
    missing = []
    for name in REQUIRED_HEADERS:
        if name.lower() not in normalized:
            missing.append(name)

    vulnerabilities = [f"Missing {h}" for h in missing]
    return {
        "present": {h: h.lower() in normalized for h in REQUIRED_HEADERS},
        "missing": missing,
        "vulnerabilities": vulnerabilities,
    }
