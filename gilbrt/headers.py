"""Heuristic browser-defense checks and verified TLS certificate inspection."""

import re
import socket
import ssl
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

import requests

from .models import Finding
from .scanner import safe_url


def analyze_headers(response: requests.Response, document: bool = True) -> list[Finding]:
    """Inspect CORS/cookies on all resources; browser document defenses on HTML."""
    findings: list[Finding] = []
    headers = response.headers
    url = safe_url(response.url)

    def add(title: str, evidence: str, advice: str, severity: str = "Warning") -> None:
        findings.append(Finding(severity, "Headers", title, url, evidence, advice))

    checks = {
        "Content-Security-Policy": "Deploy an enforced CSP with restrictive sources and nonces or hashes.",
        "Strict-Transport-Security": "Serve HTTPS and enable HSTS with an appropriate max-age.",
        "X-Frame-Options": "Use DENY/SAMEORIGIN or a restrictive CSP frame-ancestors directive.",
        "X-Content-Type-Options": "Set X-Content-Type-Options: nosniff.",
        "Referrer-Policy": "Set strict-origin-when-cross-origin, same-origin, or no-referrer.",
        "Permissions-Policy": "Restrict browser features to the origins that require them.",
    }
    csp = headers.get("Content-Security-Policy", "") if document else ""
    for name, advice in (checks.items() if document else ()):
        if not headers.get(name, "").strip():
            if name == "X-Frame-Options" and re.search(r"(?:^|;)\s*frame-ancestors\s+", csp, re.I):
                continue
            add(f"Missing {name}", "Defense header absent or empty.", advice,
                "Info" if name == "Permissions-Policy" else "Warning")
    if csp:
        directives = {}
        for item in csp.split(";"):
            parts = item.strip().lower().split()
            if parts:
                directives.setdefault(parts[0], parts[1:])
        scripts = directives.get("script-src", directives.get("default-src", []))
        if any(v in scripts for v in ("*", "'unsafe-inline'", "'unsafe-eval'", "http:", "https:", "data:")):
            add("Permissive script CSP", "Broad sources or unsafe execution keywords detected.", checks["Content-Security-Policy"])
        if "script-src" not in directives and "default-src" not in directives:
            add("CSP does not restrict scripts", "No script-src or default-src directive.", checks["Content-Security-Policy"])
    hsts = headers.get("Strict-Transport-Security", "") if document else ""
    age = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", hsts, re.I)
    if hsts and (not age or int(age.group(1)) < 15552000):
        add("Weak HSTS policy", "Missing, invalid or short max-age (<180 days).", checks["Strict-Transport-Security"])
    if hsts and urlsplit(response.url).scheme != "https":
        add("HSTS sent over HTTP", "Browsers do not accept HSTS from insecure HTTP.", checks["Strict-Transport-Security"])
    xfo = headers.get("X-Frame-Options", "") if document else ""
    if xfo and xfo.upper().strip() not in {"DENY", "SAMEORIGIN"}:
        add("Invalid X-Frame-Options", "Value is not DENY or SAMEORIGIN.", checks["X-Frame-Options"])
    xcto = headers.get("X-Content-Type-Options", "") if document else ""
    if xcto and xcto.lower().strip() != "nosniff":
        add("Invalid X-Content-Type-Options", "Value is not nosniff.", checks["X-Content-Type-Options"])
    referrer = headers.get("Referrer-Policy", "") if document else ""
    if referrer and referrer.split(",")[-1].strip().lower() not in {
        "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}:
        add("Review Referrer-Policy", "Final policy may disclose more referrer data or be invalid.", checks["Referrer-Policy"])
    permissions = headers.get("Permissions-Policy", "") if document else ""
    if permissions and ("=" not in permissions or re.search(r"=\s*\*", permissions)):
        add("Review Permissions-Policy", "Malformed or wildcard feature policy.", checks["Permissions-Policy"], "Info")
    raw = getattr(response.raw, "headers", None)
    origin = headers.get("Access-Control-Allow-Origin", "").strip()
    credentials = headers.get("Access-Control-Allow-Credentials", "").strip().lower()
    if origin == "*" and credentials == "true":
        add("Invalid credentialed wildcard CORS", "Wildcard allow-origin combined with allow-credentials=true; browsers reject credentialed reads.",
            "Use an explicit trusted origin allowlist. This invalid combination alone does not establish cross-origin data exposure.")
    if origin == "null":
        add("CORS trusts null origin", "Opaque/sandboxed origins may share the null origin; policy requires review.",
            "Use an explicit trusted origin allowlist instead of trusting null.")
    if origin and origin not in {"*", "null"} and "origin" not in {v.strip().lower() for v in headers.get("Vary", "").split(",")} and headers.get("Vary", "").strip() != "*":
        add("Review CORS cache variation", "Specific allow-origin without Vary: Origin; a static policy may be intentional.",
            "If allow-origin changes by request origin, send Vary: Origin to prevent shared-cache policy confusion.", "Info")
    if re.search(r"\b\d+\.\d+(?:\.\d+)?\b", headers.get("Server", "") + " " + headers.get("X-Powered-By", "")):
        add("Server version disclosed", "A version-like value is present in Server or X-Powered-By; value withheld.",
            "Remove unnecessary version disclosure and keep server software patched. Disclosure alone does not establish a vulnerable version.", "Info")
    cookies = raw.getlist("Set-Cookie") if raw is not None and hasattr(raw, "getlist") else []
    if not cookies and headers.get("Set-Cookie"):
        cookies = [headers["Set-Cookie"]]
    for index, header in enumerate(cookies, 1):
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except CookieError:
            cookie.clear()
        if not cookie:
            add("Unparseable cookie", f"Cookie header {index}; values withheld.", "Review cookie serialization and attributes.")
        for morsel in cookie.values():
            if morsel.key.startswith("__Secure-") and not morsel["secure"]:
                add("Invalid __Secure- cookie prefix", f"Cookie header {index}; Secure attribute absent.", "Set Secure and serve the cookie over HTTPS.")
            if morsel.key.startswith("__Host-") and (not morsel["secure"] or morsel["path"] != "/" or morsel["domain"]):
                add("Invalid __Host- cookie prefix", f"Cookie header {index}; prefix attribute requirements not met.", "Set Secure and Path=/, omit Domain, and serve the cookie over HTTPS.")
            missing = [attribute for attribute in ("secure", "httponly", "samesite") if not morsel[attribute]]
            if missing:
                add("Cookie missing defenses", f"Cookie header {index}: missing {', '.join(missing)}.",
                    "Set Secure, HttpOnly (unless JavaScript access is intentional), and appropriate SameSite.")
            same_site = morsel["samesite"].lower()
            if same_site and same_site not in {"lax", "strict", "none"}:
                add("Invalid cookie SameSite", f"Cookie header {index}; invalid SameSite.", "Use Lax, Strict, or None.")
            if same_site == "none" and not morsel["secure"]:
                add("SameSite=None without Secure", f"Cookie header {index}.", "Set Secure for cross-site cookies.")
    return findings


def analyze_tls(url: str, timeout: float = 10.0) -> list[Finding]:
    """Verify trust/hostname/expiry using default CA roots, with a bounded socket."""
    p = urlsplit(url)
    location = safe_url(url)
    if p.scheme != "https":
        return [Finding("Warning", "TLS", "Unencrypted HTTP target", location,
                        "TLS certificate check not applicable.", "Serve the application over HTTPS.")]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((p.hostname, p.port or 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=p.hostname) as secure:
                cert = secure.getpeercert()
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        days = (expiry - datetime.now(timezone.utc)).days
        return [Finding("Warning" if days < 30 else "Info", "TLS",
                        "Certificate expires soon" if days < 30 else "TLS certificate verified", location,
                        f"Expires {expiry.date().isoformat()}; {days} days remaining.",
                        "Renew before expiration and monitor certificate renewal.")]
    except ssl.SSLCertVerificationError:
        return [Finding("Critical", "TLS", "Certificate verification failed", location,
                        "Trust, hostname, or validity check failed.", "Install a trusted, unexpired certificate for the hostname.")]
    except (OSError, ssl.SSLError, KeyError, ValueError):
        return [Finding("Info", "TLS", "TLS inspection incomplete", location,
                        "Handshake or certificate parsing failed.", "Review TLS configuration and connectivity.")]
