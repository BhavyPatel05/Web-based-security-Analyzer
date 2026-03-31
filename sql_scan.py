"""
SQL injection heuristic (error-based signal).

Injects a classic tautology-style fragment in a dedicated query parameter and
searches the response body for common database error strings (MySQL, Postgres,
SQLite, Oracle, ODBC, etc.). A match suggests the input may reach a SQL engine
without safe parameterization — not proof of exploitable SQLi by itself.

Authorized targets only; many false positives/negatives possible.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

PAYLOAD = "' OR '1'='1"
SAFE_PARAM = "wbsa_sqli"

SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql error",
    r"sqlite",
    r"postgresql",
    r"ora-\d{5}",
    r"microsoft ole db",
    r"odbc sql",
    r"unclosed quotation mark",
    r"syntax error.*near",
    r"warning:\s*mysql",
]


def _inject_query(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_sql_injection(url: str, timeout: int = 15) -> dict:
    """
    GET the URL with ``SAFE_PARAM`` set to ``PAYLOAD``; flag if error patterns match.

    Returns:
        suspicious: True if a pattern matched
        vulnerabilities: list of strings for aggregation
        detail: error message on request failure
    """
    out = {"suspicious": False, "vulnerabilities": [], "detail": None}
    test_url = _inject_query(url, SAFE_PARAM, PAYLOAD)
    try:
        r = requests.get(
            test_url,
            timeout=timeout,
            headers={"User-Agent": "WebSecurityAnalyzer/1.0"},
            verify=True,
        )
        text = (r.text or "").lower()
        for pat in SQL_ERROR_PATTERNS:
            if re.search(pat, text, re.I):
                out["suspicious"] = True
                out["vulnerabilities"].append("Possible SQL injection (error-based signal)")
                out["detail"] = "Database-related error pattern in response"
                return out
    except requests.RequestException as e:
        out["detail"] = str(e)
    return out
