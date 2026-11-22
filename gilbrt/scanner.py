"""Static pattern and entropy detection with conservative evidence handling."""

import math
import re
import hashlib
import json
from collections import Counter
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit

from bs4 import BeautifulSoup, Comment

from .models import Finding
from .access_codes import detect as detect_access_codes

PATTERNS: dict[str, re.Pattern[str]] = {
    "OpenAI-style API secret": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    "Anthropic API secret": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    "Hugging Face token": re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Stripe live secret": re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "GitHub token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
}
ASSIGNMENT = re.compile(
    r'''(?ix)["']?\b(?:api[_-]?key|secret|token|password|auth)\b["']?\s*[:=]\s*["']([^"'\r\n]{8,512})["']'''
)
KEYWORDS = re.compile(r"\b(?:TODO|FIXME|password|secret|debug|internal|admin)\b", re.I)
CONTENT_CHECKS = {"passwords", "access-codes", "api-keys", "tokens", "private-keys", "entropy", "comments"}
PASSWORD = re.compile(
    r'''(?ix)(?<![\w$.-])["']?(?:[\w$.-]*?(?:password|passwd|pwd)|pass)["']?\s*(?::|=(?!=))\s*(?:"([^"\r\n]{1,512})"|'([^'\r\n]{1,512})'|`([^`\r\n]{1,512})`|([^\s,;<>"'`}{]{1,512}))'''
)


def pattern_category(label: str) -> str:
    """Map provider patterns to selectable content checks."""
    if label == "Private key":
        return "private-keys"
    if label in {"Slack token", "GitHub token", "JWT", "Hugging Face token"}:
        return "tokens"
    return "api-keys"


def entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values())


def mask(value: str) -> str:
    """Mask short values fully and expose at most four characters at each end."""
    return "[REDACTED]" if len(value) < 16 else value[:4] + "…[REDACTED]…" + value[-4:]


def safe_url(url: str) -> str:
    """Remove credentials, query values and paths that may contain credentials."""
    try:
        p = urlsplit(url)
        host = p.hostname or "unknown"
        if ":" in host:
            host = f"[{host}]"
        if p.port:
            host += f":{p.port}"
        # Paths can contain opaque access tokens, so reports intentionally omit them.
        identifier = hashlib.sha256(url.encode()).hexdigest()[:12]
        return urlunsplit((p.scheme, host, f"/[resource-{identifier}]", "", ""))
    except ValueError:
        return "[URL omitted]"


def scan(text: str, url: str, html: bool = False, checks: set[str] | None = None,
         on_secret: Callable[[Finding, str], None] | None = None) -> list[Finding]:
    """Scan content without persisting raw snippets, comments, or key material."""
    findings: list[Finding] = []
    enabled = CONTENT_CHECKS if checks is None else checks
    seen: set[tuple[str, str]] = set()
    location = safe_url(url)
    if enabled & {"passwords", "access-codes"}:
        # HTML can contain megabytes of encoded images. Lex only script contents
        # and event handlers; preserve offsets for script line reporting.
        code_sources = [(text, 0)]
        if html:
            code_sources = [(m.group(1), m.start(1)) for m in re.finditer(
                r"<script\b[^>]*>([\s\S]*?)</script\s*>", text, re.I)]
            soup = BeautifulSoup(text, "html.parser")
            for node in soup.find_all(True):
                for name, value in node.attrs.items():
                    if name.startswith("on") and isinstance(value, str):
                        offset = sum(len(line) for line in text.splitlines(keepends=True)[:max(0, (node.sourceline or 1) - 1)])
                        code_sources.append((value, offset))
        for candidate, base_offset in ((c, offset) for source, offset in code_sources for c in detect_access_codes(source)):
            if "access-codes" not in enabled and not candidate.password:
                continue
            kind = "Password" if candidate.password else "Access code"
            key = (kind.lower(), candidate.value)
            if key in seen:
                continue
            seen.add(key)
            line = text.count("\n", 0, base_offset + candidate.offset) + 1
            title = f"Hardcoded {kind.lower()} {'comparison' if candidate.operator in {'==', '===', '!=', '!=='} else 'assignment'}"
            if not candidate.confident_name:
                title = "Hardcoded literal in conditional (review)"
            findings.append(Finding("Critical" if candidate.password else "Warning" if candidate.confident_name else "Info", kind, title, location,
                                    f"Line {line}; operator {candidate.operator}; {mask(candidate.value)}; static candidate only",
                                    "Move access checks to the server; rotate real exposed access codes. Verify whether this comparison controls access."))
            if on_secret:
                on_secret(findings[-1], candidate.value)
    def password_candidate(value: str, line: int, source: str) -> None:
        """Record a password candidate without persisting its plaintext value."""
        if not value.strip() or ("password", value) in seen:
            return
        seen.add(("password", value))
        findings.append(Finding("Critical", "Password", "Potential exposed password", location,
                                f"Line {line}; {source}; {mask(value)}; literal candidate, not validated",
                                "Remove exposed passwords, rotate real credentials and keep authentication server-side."))
        if on_secret:
            on_secret(findings[-1], value)

    if "passwords" in enabled:
        for match in PASSWORD.finditer(text):
            password_candidate(next(v for v in match.groups() if v is not None),
                               text.count("\n", 0, match.start()) + 1, "password assignment")
        if html:
            soup = BeautifulSoup(text, "html.parser", store_line_numbers=True)
            visible = soup.get_text(" ", strip=True)
            for match in PASSWORD.finditer(visible):
                password_candidate(next(v for v in match.groups() if v is not None), 1,
                                   "visible HTML text; line approximate")
            for node in soup.find_all(True):
                identity = " ".join(str(node.get(k, "")) for k in ("name", "id", "type"))
                if node.name in {"input", "textarea"} and re.search(r"password|passwd|pwd|\bpass\b", identity, re.I):
                    value = node.get("value", "") if node.name == "input" else node.get_text()
                    password_candidate(str(value), node.sourceline or 1, "prefilled HTML field")
                for name, value in node.attrs.items():
                    if re.search(r"^data-.*(?:password|passwd|pwd)$", name, re.I) and isinstance(value, str):
                        password_candidate(value, node.sourceline or 1, "HTML data attribute")
            for row in soup.find_all("tr"):
                cells = row.find_all(["td", "th"], recursive=False)
                if len(cells) >= 2 and re.fullmatch(r"(?:[\w.-]*?(?:password|passwd|pwd)|pass)\s*:?", cells[0].get_text(strip=True), re.I):
                    password_candidate(cells[1].get_text(strip=True), row.sourceline or 1, "HTML table password field")
    for label, pattern in PATTERNS.items():
        if pattern_category(label) not in enabled:
            continue
        for match in pattern.finditer(text):
            value = match.group()
            if (label, value) in seen:
                continue
            seen.add((label, value))
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding(
                "Warning" if label in {"JWT", "Google API key"} else "Critical",
                "Secret", f"Potential {label}", location,
                f"Line {line}; {mask(value)}; static match only",
                "Verify ownership and intended exposure; rotate exposed credentials and move secrets server-side.",
            ))
            if on_secret:
                on_secret(findings[-1], value)
    for match in ASSIGNMENT.finditer(text):
        if "entropy" not in enabled:
            break
        value = match.group(1)
        if len(value) >= 20 and entropy(value) >= 3.5 and not any(v == value and kind != "access code" for kind, v in seen):
            seen.add(("entropy", value))
            findings.append(Finding("Warning", "Secret", "High-entropy sensitive assignment", location,
                                    f"Line {text.count(chr(10), 0, match.start()) + 1}; {mask(value)}",
                                    "Review this candidate; use a server-side secret store if confidential."))
            if on_secret:
                on_secret(findings[-1], value)
    # Skip quoted strings before matching JS comments, including trailing // notes.
    comment_pattern = re.compile(
        r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|(/\*[\s\S]*?\*/|//[^\r\n]*)'''
    )
    comment_texts = [m.group(1) for m in comment_pattern.finditer(text) if m.group(1)]
    if html:
        soup = BeautifulSoup(text, "html.parser")
        comment_texts.extend(str(c) for c in soup.find_all(string=lambda s: isinstance(s, Comment)))
    for comment in comment_texts:
        if "comments" not in enabled:
            break
        words = sorted({m.group().lower() for m in KEYWORDS.finditer(comment)})
        if words:
            findings.append(Finding("Info", "Comment", "Sensitive comment keywords", location,
                                    "Keywords: " + ", ".join(words) + "; comment text withheld",
                                    "Remove internal notes and confidential material from production assets."))
    # Decode published source-map sourcesContent so escaped strings are searchable.
    if not html and '"sourcesContent"' in text:
        try:
            document = json.loads(text)
            sources = document.get("sourcesContent", []) if isinstance(document, dict) else []
            if isinstance(sources, list):
                for index, source in enumerate(sources[:1000]):
                    if isinstance(source, str) and '"sourcesContent"' not in source:
                        nested_values: dict[int, str] = {}
                        nested = scan(source, url, checks=enabled,
                                      on_secret=(lambda finding, value: nested_values.__setitem__(id(finding), value)) if on_secret else None)
                        for finding in nested:
                            findings.append(Finding(finding.severity, finding.category, finding.title, finding.url,
                                                    f"Source-map source {index}; {finding.evidence}", finding.remediation))
                            if on_secret and id(finding) in nested_values:
                                on_secret(findings[-1], nested_values[id(finding)])
        except (ValueError, RecursionError):
            pass
    return findings
