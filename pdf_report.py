"""Generate PDF security reports using ReportLab."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def _build_recommendations(vulnerabilities: list[str]) -> list[str]:
    """
    Map detected findings to actionable remediation guidance (high-level).
    Order is stable; duplicates are merged.
    """
    recs: list[str] = []
    seen: set[str] = set()

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            recs.append(msg)

    for v in vulnerabilities:
        vl = v.lower()
        if "missing" in vl and "content-security-policy" in vl:
            add(
                "Deploy a strict Content-Security-Policy (default-src, script-src, "
                "object-src 'none') and iterate with report-only mode before enforcing."
            )
        if "missing" in vl and "x-frame-options" in vl:
            add(
                "Set X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors in CSP) "
                "to reduce clickjacking risk."
            )
        if "strict-transport-security" in vl and "missing" in vl:
            add(
                "Enable HTTP Strict-Transport-Security with a sensible max-age and "
                "includeSubDomains where appropriate."
            )
        if "x-xss-protection" in vl and "missing" in vl:
            add(
                "Add defense-in-depth: modern browsers rely on CSP; X-XSS-Protection is "
                "legacy but may still be set for older clients."
            )
        if "open port" in vl:
            add(
                "Review exposed TCP services: close unused ports, restrict with firewalls "
                "or security groups, and keep only required daemons patched."
            )
        if "possible xss" in vl or ("xss" in vl and "protection" not in vl):
            add(
                "Treat reflected XSS: encode/escape output by context, validate input, "
                "and use CSP to restrict script execution."
            )
        if "sql injection" in vl:
            add(
                "Use parameterized queries / prepared statements; avoid string "
                "concatenation for SQL; least-privilege DB accounts."
            )
        if "ssl" in vl or "certificate" in vl or "tls" in vl:
            add(
                "Remediate TLS: valid certificate chain, strong ciphers, TLS 1.2+, and "
                "monitor expiry with automation."
            )
        if "https not used" in vl or "not served over https" in vl:
            add(
                "Enforce HTTPS end-to-end: redirects from HTTP, HSTS, and secure cookies."
            )
        if "invalid url" in vl or "request failed" in vl:
            add(
                "Verify the target URL, DNS, TLS trust, and that the scanner can reach "
                "the host from its network context."
            )

    if not recs and vulnerabilities:
        add(
            "Review each finding manually; prioritize by impact, reproduce in a safe "
            "environment, and track fixes through your SDLC."
        )
    if not vulnerabilities:
        add(
            "Maintain monitoring: schedule periodic scans, dependency updates, and "
            "penetration tests; automated checks are not exhaustive."
        )

    # Generic hardening if many header issues
    if sum(1 for v in vulnerabilities if v.startswith("Missing ")) >= 2:
        add(
            "Centralize security headers at the reverse proxy, CDN, or framework "
            "middleware for consistent coverage."
        )

    return recs


def write_pdf_report(
    output_dir: str,
    scan_id: str,
    url: str,
    score: int,
    risk: str,
    vulnerabilities: list[str],
    details: dict | None = None,
) -> str:
    """
    Write a PDF report: URL, scan timestamp, score, risk, findings, and
    recommended fixes. Returns absolute path to the file.
    """
    os.makedirs(output_dir, exist_ok=True)
    safe_id = "".join(c for c in scan_id if c.isalnum())[:32] or "scan"
    filename = f"security_report_{safe_id}.pdf"
    path = os.path.join(output_dir, filename)

    now = datetime.now(timezone.utc)
    scan_date_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    recommendations = _build_recommendations(vulnerabilities)

    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "BodyJustify",
        parent=styles["BodyText"],
        alignment=TA_JUSTIFY,
        spaceAfter=8,
        fontSize=10,
        leading=14,
    )
    story = []

    story.append(Paragraph("Web Based Security Analyzer", styles["Title"]))
    story.append(
        Paragraph(
            "<i>Security assessment report</i>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>Website URL</b>", styles["Heading3"]))
    story.append(Paragraph(_escape_xml(url), styles["Normal"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Scan date</b>", styles["Heading3"]))
    story.append(Paragraph(scan_date_str, styles["Normal"]))
    story.append(Paragraph(f"<b>Scan ID:</b> {_escape_xml(scan_id)}", styles["Normal"]))
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>Security score</b>", styles["Heading3"]))
    story.append(
        Paragraph(
            f"<b>{score}</b> out of 100 &nbsp;|&nbsp; <b>Risk level:</b> {_escape_xml(risk)}",
            styles["Heading2"],
        )
    )
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>Detected vulnerabilities</b>", styles["Heading3"]))
    if not vulnerabilities:
        story.append(Paragraph("No issues were reported by this automated scan.", body))
    else:
        for i, v in enumerate(vulnerabilities, 1):
            story.append(Paragraph(f"{i}. {_escape_xml(v)}", body))
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 14))
    story.append(Paragraph("<b>Recommended fixes</b>", styles["Heading3"]))
    story.append(
        Paragraph(
            "<i>The following recommendations are general guidance mapped to typical "
            "finding types. Validate against your stack and threat model.</i>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 8))
    for i, rec in enumerate(recommendations, 1):
        story.append(Paragraph(f"{i}. {_escape_xml(rec)}", body))

    if details and details.get("crawler"):
        c = details["crawler"]
        story.append(Spacer(1, 14))
        story.append(Paragraph("<b>Internal links (crawler)</b>", styles["Heading3"]))
        story.append(
            Paragraph(
                f"Discovered {c.get('count', 0)} same-origin link(s) for scope review.",
                styles["Normal"],
            )
        )
        for link in (c.get("internal_links") or [])[:25]:
            story.append(Paragraph(f"• {_escape_xml(link)}", styles["Normal"]))

    doc = SimpleDocTemplate(
        path,
        pagesize=letter,
        rightMargin=inch * 0.75,
        leftMargin=inch * 0.75,
        topMargin=inch * 0.75,
        bottomMargin=inch * 0.75,
    )
    doc.build(story)
    return path


def _escape_xml(text: str) -> str:
    s = str(text)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s
