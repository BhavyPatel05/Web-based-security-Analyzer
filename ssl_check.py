import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def _parse_asn1_time(s):
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_ssl_certificate(url, timeout=10):

    out = {
        "https": False,
        "valid": None,
        "expires": None,
        "issuer": None,
        "subject": None,
        "error": None,
        "vulnerabilities": [],
    }

    parsed = urlparse(url)

    if parsed.scheme.lower() != "https":
        out["vulnerabilities"].append("HTTPS not used — transport not encrypted")
        return out

    out["https"] = True
    host = parsed.hostname

    if not host:
        out["error"] = "No hostname in URL"
        return out

    port = parsed.port or 443

    # ✅ FIX
    ctx = ssl.create_default_context()
    ctx.check_hostname = True

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:

                cert = ssock.getpeercert()

                if not cert:
                    out["valid"] = False
                    out["vulnerabilities"].append("No peer certificate received")
                    return out

                not_after = cert.get("notAfter")

                if not_after:
                    out["expires"] = not_after
                    exp = _parse_asn1_time(not_after)

                    if exp and exp < datetime.now(timezone.utc):
                        out["valid"] = False
                        out["vulnerabilities"].append("SSL certificate expired")
                    else:
                        out["valid"] = True
                else:
                    out["valid"] = True

                subj = cert.get("subject")
                if subj:
                    flat = {k: v for part in subj for k, v in part}
                    out["subject"] = flat.get("commonName") or str(subj)

                iss = cert.get("issuer")
                if iss:
                    flat_i = {k: v for part in iss for k, v in part}
                    out["issuer"] = flat_i.get("organizationName") or flat_i.get("commonName") or str(iss)

    except ssl.SSLError as e:
        out["valid"] = False
        out["error"] = str(e)
        out["vulnerabilities"].append(f"SSL/TLS error: {e}")

    except OSError as e:
        out["error"] = str(e)
        out["vulnerabilities"].append(f"Connection error: {e}")
    return out

# import socket
# import ssl
# from datetime import datetime, timezone
# from typing import Any
# from urllib.parse import urlparse


# def _parse_asn1_time(s: str) -> datetime | None:
#     try:
#         return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
#     except ValueError:
#         return None


# def check_ssl_certificate(url: str, timeout: int = 10) -> dict[str, Any]:

#     out: dict[str, Any] = {
#         "https": False,
#         "valid": None,
#         "expires": None,
#         "issuer": None,
#         "subject": None,
#         "error": None,
#         "vulnerabilities": [],
#     }

#     parsed = urlparse(url)

#     if parsed.scheme.lower() != "https":
#         out["vulnerabilities"].append("HTTPS not used — transport not encrypted")
#         return out

#     out["https"] = True
#     host = parsed.hostname

#     if not host:
#         out["error"] = "No hostname in URL"
#         return out

#     port = parsed.port or 443

#     # ✅ FIX — create SSL context
#     ctx = ssl.create_default_context()
#     ctx.check_hostname = True

#     try:

#         with socket.create_connection((host, port), timeout=timeout) as sock:

#             with ctx.wrap_socket(sock, server_hostname=host) as ssock:

#                 cert = ssock.getpeercert()

#                 if not cert:
#                     out["valid"] = False
#                     out["vulnerabilities"].append("No peer certificate received")
#                     return out

#                 not_after = cert.get("notAfter")

#                 if not_after:
#                     out["expires"] = not_after
#                     exp = _parse_asn1_time(not_after)

#                     if exp and exp < datetime.now(timezone.utc):
#                         out["valid"] = False
#                         out["vulnerabilities"].append("SSL certificate expired")
#                     else:
#                         out["valid"] = True

#                 subj = cert.get("subject")

#                 if subj:
#                     flat = {k: v for part in subj for k, v in part}
#                     out["subject"] = flat.get("commonName") or str(subj)

#                 iss = cert.get("issuer")

#                 if iss:
#                     flat_i = {k: v for part in iss for k, v in part}
#                     out["issuer"] = (
#                         flat_i.get("organizationName")
#                         or flat_i.get("commonName")
#                         or str(iss)
#                     )

#     except ssl.SSLError as e:

#         out["valid"] = False
#         out["error"] = str(e)
#         out["vulnerabilities"].append(f"SSL/TLS error: {e!s}")

#     except OSError as e:

#         out["error"] = str(e)
#         out["vulnerabilities"].append(f"Connection error (SSL check): {e!s}")

#     return out