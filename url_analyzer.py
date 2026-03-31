"""
URL analysis: validate scheme/host, perform initial HTTP fetch, and crawl same-origin links.

These checks establish whether the target is reachable and whether the connection
uses HTTPS after redirects (transport security baseline).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def validate_url_shape(url: str) -> dict:
    """
    Verify the string is a usable http(s) URL with scheme and netloc.

    Security relevance: Only http/https are scanned; other schemes are rejected to
    avoid ambiguous or unsafe handlers.
    """
    out = {"valid": False, "https": False, "error": None}
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        out["error"] = "Invalid URL (need scheme and host, e.g. https://example.com)"
        return out
    if parsed.scheme.lower() not in ("http", "https"):
        out["error"] = "Only http and https are supported"
        return out
    out["valid"] = True
    out["https"] = parsed.scheme.lower() == "https"
    return out

def validate_and_fetch(url: str, timeout: int = 15) -> dict:

    out: dict = {
        "url": url,
        "valid": False,
        "status_code": None,
        "https": False,
        "final_url": None,
        "error": None,
        "vulnerabilities": [],
    }

    shape = validate_url_shape(url)

    if not shape["valid"]:
        out["error"] = shape["error"]
        out["vulnerabilities"].append("Invalid URL format")
        return out

    out["valid"] = True
    out["https"] = shape["https"]

    try:

        r = requests.get(
            url,
            timeout=(5, 15),
            allow_redirects=True,
            headers={"User-Agent": "WebSecurityAnalyzer/1.0"},
            verify=True,
        )

        out["status_code"] = r.status_code
        out["final_url"] = r.url

        if urlparse(r.url).scheme.lower() != "https":
            out["vulnerabilities"].append("Final response not served over HTTPS")

    except requests.RequestException as e:

        out["error"] = str(e)
        out["vulnerabilities"].append(f"Request failed: {e!s}")

    return out


def crawl_internal_links(base_url: str, html: str, max_links: int = 50) -> dict:
    """
    Parse HTML and collect internal links (same host) for attack-surface awareness.

    Security relevance: Surfaces additional entry points on the same origin that
    might be tested manually or in a follow-up scan (not a vulnerability by itself).
    """
    base = urlparse(base_url)
    host = base.netloc.lower()
    found: list[str] = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            if len(found) >= max_links:
                break
            href = a["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            absolute = urljoin(base_url, href)
            p = urlparse(absolute)
            if p.netloc.lower() == host and p.scheme in ("http", "https"):
                clean = absolute.split("#")[0]
                if clean not in found:
                    found.append(clean)
    except Exception:
        pass
    return {"internal_links": found, "count": len(found)}
