"""Bounded same-origin GET crawler; redirects are validated before each request."""

import time
import re
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup
from bs4.dammit import EncodingDetector

from .models import Finding
from .scanner import safe_url
from .scope import DO_NOT_TEST, ExcludedTarget, blocked, domain_name

USER_AGENT = "gilbrt/0.1 (authorized security audit)"
MAX_BYTES = 2 * 1024 * 1024


def normalize(url: str) -> str:
    """Validate an HTTP URL, reject credentials and strip its fragment."""
    if re.match(r"^https?://https?://", url, re.I) or "\\" in url or any(c.isspace() for c in url):
        raise ValueError("Use a single HTTP(S) prefix without backslashes or whitespace")
    p = urlsplit(urldefrag(url)[0])
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        raise ValueError("Use an absolute HTTP(S) URL without credentials")
    _ = p.port
    return urlunsplit((p.scheme, p.netloc.lower(), p.path or "/", p.query, ""))


@dataclass
class Resource:
    """One fetched resource. Body is kept only in memory."""

    url: str
    body: str
    response: requests.Response
    html: bool


class ScopedClient:
    """A serial client enforcing exact scheme/netloc, limits and TLS verification."""

    def __init__(self, target: str, delay: float = 1.0, timeout: float = 15.0,
                 max_resource_bytes: int = 16 * 1024 * 1024,
                 exclude_domains: list[str] | None = None):
        self.target = normalize(target)
        self.exclusions = DO_NOT_TEST + tuple(domain_name(d) for d in exclude_domains or [])
        if blocked(self.target, self.exclusions):
            raise ExcludedTarget("Target is on the do-not-test website list")
        p = urlsplit(self.target)
        self.origin = (p.scheme, p.netloc)
        self.delay = delay
        self.timeout = timeout
        self.max_resource_bytes = max_resource_bytes
        self.last_request: float | None = None
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.errors: list[Finding] = []

    def allowed(self, url: str) -> bool:
        """Require both exact netloc and scheme (no HTTPS downgrade)."""
        try:
            p = urlsplit(normalize(url))
            return (p.scheme, p.netloc) == self.origin and not blocked(url, self.exclusions)
        except ValueError:
            return False

    def pace(self) -> None:
        """Wait at least delay seconds between request starts."""
        if self.last_request is not None:
            time.sleep(max(0.0, self.delay - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()

    def get(self, url: str, permitted: Callable[[str], bool] | None = None, headers: dict[str, str] | None = None,
            fresh: bool = False, follow_redirects: bool = True, method: str = "GET") -> requests.Response | None:
        """Read-only HTTP methods with bounded bodies and per-hop scope checks."""
        if method not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("Only GET, HEAD and OPTIONS checks are supported")
        current = normalize(url)
        for _ in range(6):
            if not self.allowed(current) or (permitted and not permitted(current)):
                self.issue("Scope or robots blocked request", current)
                return None
            self.pace()
            # Fresh sessions prevent cookies from contaminating isolation probes.
            session = requests.Session() if fresh else self.session
            session.trust_env = False
            try:
                request = session.get if method == "GET" else lambda *a, **kw: session.request(method, *a, **kw)
                with request(current, headers=headers, timeout=self.timeout,
                                 allow_redirects=False, stream=True) as response:
                    if response.status_code in {301, 302, 303, 307, 308}:
                        if not follow_redirects:
                            self.issue("Active probe redirect refused", current)
                            return None
                        location = response.headers.get("Location")
                        if not location:
                            self.issue("Redirect without Location", current)
                            return None
                        current = normalize(urljoin(current, location))
                        continue
                    body = bytearray()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > self.max_resource_bytes:
                            self.issue(f"Resource exceeded {self.max_resource_bytes} byte limit", current)
                            return None
                    response._content = bytes(body)
                    response._content_consumed = True
                    content_type = response.headers.get("Content-Type", "")
                    if "html" in content_type.lower() and not re.search(r"charset\s*=", content_type, re.I):
                        declared = EncodingDetector.find_declared_encoding(response.content[:4096], is_html=True)
                        if declared:
                            response.encoding = declared
                    return response
            except (requests.RequestException, ValueError):
                self.issue("Network, URL or TLS request failure", current)
                return None
            finally:
                if fresh:
                    session.close()
        self.issue("Redirect limit reached", current)
        return None

    def issue(self, title: str, url: str) -> None:
        """Record a safe diagnostic without exception text or raw URLs."""
        self.errors.append(Finding("Info", "Coverage", title, safe_url(url),
                                   "Resource could not be fully audited.", "Review scope, availability and server logs."))


class Crawler:
    """Crawl document links to depth; script assets do not consume document depth."""

    def __init__(self, client: ScopedClient, max_depth: int = 2, max_pages: int = 25,
                 ignore_robots: bool = False, include_urls: list[str] | None = None,
                 discover_sitemaps: bool = False):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.attempts = 0
        self.ignore_robots = ignore_robots
        self.robots: RobotFileParser | None = None
        self.block_all = False
        self.discover_sitemaps = discover_sitemaps
        self.sitemaps: list[str] = []
        self.visited: set[str] = set()
        self.include_urls = [normalize(urljoin(client.target, url)) for url in include_urls or []]
        if any(not client.allowed(url) for url in self.include_urls):
            raise ValueError("Included URLs must match the target's exact origin")

    def load_robots(self) -> None:
        """Treat missing robots as unrestricted, other failures as deny-all."""
        if self.ignore_robots:
            if self.discover_sitemaps:
                self.client.errors.append(Finding("Info", "Coverage", "Sitemap discovery disabled by robots override",
                    safe_url(self.client.target), "Sitemaps were requested, but robots.txt declarations were not loaded because robots handling was disabled.",
                    "Respect robots.txt to discover declared sitemaps, or supply known same-origin page URLs explicitly."))
            return
        url = urljoin(self.client.target, "/robots.txt")
        response = self.client.get(url)
        if response is None or response.status_code not in {200, 404, 410}:
            self.block_all = True
            self.client.issue("robots.txt unavailable; crawl blocked", url)
        elif response.status_code == 200:
            self.robots = RobotFileParser()
            self.robots.parse(response.text.splitlines())
            if self.discover_sitemaps:
                self.sitemaps = (self.robots.site_maps() or [])[:self.max_pages]
            delay = self.robots.crawl_delay("gilbrt") or self.robots.crawl_delay("*")
            if delay:
                self.client.delay = max(self.client.delay, float(delay))

    def permitted(self, url: str) -> bool:
        """Evaluate scope and robots for every requested URL, including redirects."""
        return self.client.allowed(url) and not self.block_all and (
            self.ignore_robots or self.robots is None or self.robots.can_fetch("gilbrt", url))

    def crawl(self) -> Iterator[Resource]:
        """Yield fetched source resources, capped by total resource attempts."""
        self.load_robots()
        seeds = list(dict.fromkeys([self.client.target] + self.include_urls + self.sitemaps))
        queue = deque((url, 0, url != self.client.target) for url in seeds)
        scheduled = set(seeds)
        sitemap_urls = set(self.sitemaps)
        attempts = 0
        while queue and attempts < self.max_pages:
            url, depth, asset = queue.popleft()
            if url in self.visited or not self.permitted(url):
                continue
            attempts += 1
            self.attempts = attempts
            self.visited.add(url)
            response = self.client.get(url, self.permitted)
            if response is None:
                continue
            if response.url != url and response.url in self.visited:
                continue  # A redirect to an already scanned resource is not another finding source.
            self.visited.add(response.url)
            content_type = response.headers.get("Content-Type", "").lower()
            html = "html" in content_type
            if url in sitemap_urls:
                # Do not process DTDs/entities or treat arbitrary XML as a sitemap.
                xml_markup = response.content.replace(b"\x00", b"").upper()
                if b"<!DOCTYPE" in xml_markup or b"<!ENTITY" in xml_markup:
                    self.client.issue("Unsafe sitemap XML skipped", response.url)
                    continue
                try:
                    root = ElementTree.fromstring(response.content)
                    kind = root.tag.rsplit("}", 1)[-1]
                    if kind not in {"urlset", "sitemapindex"}:
                        raise ValueError("Not a sitemap")
                    for entry in root:
                        if len(scheduled) >= self.max_pages * 10:
                            break
                        for node in entry:
                            if len(scheduled) >= self.max_pages * 10:
                                break
                            if node.tag.rsplit("}", 1)[-1] != "loc" or not node.text:
                                continue
                            candidate = normalize(urljoin(response.url, node.text.strip()))
                            if candidate not in scheduled and self.permitted(candidate):
                                scheduled.add(candidate)
                                if kind == "sitemapindex":
                                    sitemap_urls.add(candidate)
                                queue.append((candidate, 0, kind == "sitemapindex"))
                except (ElementTree.ParseError, ValueError):
                    self.client.issue("Invalid sitemap skipped", response.url)
                continue
            if not html and not asset and not any(kind in content_type for kind in (
                    "javascript", "text/css", "application/json", "text/plain", "text/x-shellscript", "application/x-sh")):
                continue
            yield Resource(response.url, response.text, response, html)
            candidates = []
            if html:
                soup = BeautifulSoup(response.text, "html.parser")
                candidates = [(s.get("src"), depth, True) for s in soup.find_all("script", src=True)]
                candidates.extend((node.get("href"), depth, True) for node in soup.find_all("link", href=True)
                                  if set(node.get("rel", [])) & {"modulepreload", "stylesheet"} or node.get("as") == "script")
                if depth < self.max_depth:
                    candidates.extend((a.get("href"), depth + 1, False) for a in soup.find_all("a", href=True))
                    candidates.extend((a.get("src"), depth + 1, False)
                                      for a in soup.find_all(["iframe", "frame"], src=True))
            else:
                # Fetch only source maps explicitly referenced by fetched assets.
                candidates.extend((m.group(1), depth, True) for m in re.finditer(
                    r"[#@]\s*sourceMappingURL=([^\s*]+)", response.text))
                if "text/css" in content_type:
                    candidates.extend((m.group(1), depth, True) for m in re.finditer(
                        r'''@import\s+(?:url\(\s*)?["']([^"'\r\n]+)["']''', response.text, re.I))
                if "javascript" in content_type or urlsplit(response.url).path.endswith((".js", ".mjs")):
                    candidates.extend((m.group(1), depth, True) for m in re.finditer(
                        r'''(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["']((?:\.{1,2}/|/|https?://)[^"'\r\n]+)["']''', response.text))
            for href, next_depth, is_asset in candidates:
                try:
                    candidate = normalize(urljoin(response.url, href))
                except (ValueError, TypeError):
                    continue
                if candidate not in scheduled and self.permitted(candidate):
                    # Keep queued memory bounded on pages with enormous link lists.
                    if len(scheduled) >= self.max_pages * 10:
                        if not any(f.title == "Discovery queue limit reached" for f in self.client.errors):
                            self.client.issue("Discovery queue limit reached", self.client.target)
                        break
                    scheduled.add(candidate)
                    queue.append((candidate, next_depth, is_asset))
        if queue:
            self.client.errors.append(Finding("Info", "Coverage", "Resource budget reached", safe_url(self.client.target),
                f"Attempted {attempts} resources; {len(queue)} queued references were not fetched. No credentials were validated.",
                "Review scope and increase --max-pages to inspect more discovered resources."))
