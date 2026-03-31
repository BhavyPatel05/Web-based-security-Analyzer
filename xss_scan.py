"""
Reflected XSS (cross-site scripting) heuristic check.

Sends a benign test payload in a dedicated query parameter and checks whether
the raw or encoded payload appears in the HTML response. Reflection suggests the
application might render user input without proper encoding — a prerequisite for
reflected XSS (further context-specific testing is required).

Authorized targets only; noisy and not exhaustive.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests

PAYLOAD = "<script>alert(1)</script>"
SAFE_PARAM = "wbsa_xss"


def _inject_query(url: str, param: str, value: str) -> str:
    """Merge ``param=value`` into the URL query string."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_reflected_xss(url: str, timeout: int = 15) -> dict:
    """
    Request the URL with ``SAFE_PARAM`` set to ``PAYLOAD`` and inspect the body.

    If the literal payload or obvious script-like reflection appears, report
    possible XSS. Network errors are recorded in ``detail`` only.
    """
    out = {"reflected": False, "vulnerabilities": [], "detail": None}
    test_url = _inject_query(url, SAFE_PARAM, PAYLOAD)
    try:
        r = requests.get(
            test_url,
            timeout=timeout,
            headers={"User-Agent": "WebSecurityAnalyzer/1.0"},
            verify=True,
        )
        body = r.text or ""
        if PAYLOAD in body:
            out["reflected"] = True
            out["vulnerabilities"].append("Possible XSS (reflected payload)")
            out["detail"] = "Payload reflected in response"
            return out
        encoded = quote(PAYLOAD, safe="")
        if encoded in body or re.search(re.escape("<script>"), body, re.I):
            if "<script" in body.lower() and PAYLOAD.lower() in body.lower():
                out["reflected"] = True
                out["vulnerabilities"].append("Possible XSS (script-like reflection)")
                out["detail"] = "Script-like content in response"
    except requests.RequestException as e:
        out["detail"] = str(e)
    return out
