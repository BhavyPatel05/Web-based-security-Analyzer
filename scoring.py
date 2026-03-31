"""
Security score and risk band from aggregated finding strings.

Weights align with the product spec: headers, exposed ports, XSS, SQLi signals,
and HTTPS/SSL issues each reduce the score from a baseline of 100.
"""

from __future__ import annotations

import re

from headers_check import REQUIRED_HEADERS

# Scoring weights
SCORE_MISSING_HEADER = 10
SCORE_OPEN_PORT = 15
SCORE_XSS = 25
SCORE_SQLI = 30
SCORE_HTTPS_ISSUE = 10
SCORE_SSL_ISSUE = 10


def compute_score(vulnerabilities: list[str]) -> tuple[int, str]:
    """
    Start at 100; apply deductions per matched finding type, then clamp to [0, 100].

    Risk bands: Low >= 80, Medium 50–79, High < 50.
    """
    score = 100
    for v in vulnerabilities:
        if v.startswith("Missing ") and any(h in v for h in REQUIRED_HEADERS):
            score -= SCORE_MISSING_HEADER
        elif re.match(r"^Open port \d+$", v, re.I):
            score -= SCORE_OPEN_PORT
        elif "XSS" in v:
            score -= SCORE_XSS
        elif "SQL injection" in v:
            score -= SCORE_SQLI
        elif "HTTPS not used" in v or "not served over HTTPS" in v:
            score -= SCORE_HTTPS_ISSUE
        elif "SSL" in v or "certificate" in v.lower():
            score -= SCORE_SSL_ISSUE

    score = max(0, min(100, score))
    if score >= 80:
        risk = "Low"
    elif score >= 50:
        risk = "Medium"
    else:
        risk = "High"
    return score, risk
