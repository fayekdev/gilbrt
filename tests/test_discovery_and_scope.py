"""Exercise expanded discovery and execution only against a loopback fixture."""

import json
import io
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

import requests

from gilbrt.active import load_config, run_active
from gilbrt.cli import main, parser, run_audit
from gilbrt.crawler import Crawler, ScopedClient
from gilbrt.scope import blocked


class Handler(BaseHTTPRequestHandler):
    visits = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.visits.append(("GET", self.path))
        origin = f"http://127.0.0.1:{self.server.server_port}"
        routes = {
            "/robots.txt": ("text/plain", f"User-agent: *\nDisallow: /blocked\nSitemap: {origin}/index.xml\nSitemap: https://outside.invalid/map.xml"),
            "/": ("text/html", '<link rel="stylesheet" href="/style.css"><iframe src="/frame"></iframe>'),
            "/style.css": ("text/css", '@import url("/theme.css"); @import "https://outside.invalid/external.css";'),
            "/theme.css": ("text/css", "/*# sourceMappingURL=/theme.map */"),
            "/theme.map": ("application/json", '{"sourcesContent":["fixture"]}'),
            "/frame": ("text/html", '<iframe src="/deep"></iframe>'),
            "/index.xml": ("application/xml", f'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><sitemap><loc>{origin}/pages.xml</loc></sitemap></sitemapindex>'),
            "/pages.xml": ("application/xml", f'<urlset><url><loc>{origin}/hidden</loc></url><url><loc>{origin}/blocked</loc></url><url><loc>https://outside.invalid/page</loc></url></urlset>'),
            "/hidden": ("text/html", "<p>Discovered</p>"),
            "/unsafe.xml": ("application/xml", '<!DOCTYPE urlset [<!ENTITY x "fixture">]><urlset>&x;</urlset>'),
            "/redirect": ("text/plain", ""),
        }
        kind, body = routes.get(self.path, ("text/html", "<p>fixture</p>"))
        self.send_response(302 if self.path == "/redirect" else 200)
        if self.path == "/redirect":
            self.send_header("Location", "/hidden")
        self.send_header("Content-Type", kind)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_HEAD(self):
        self.visits.append(("HEAD", self.path))
        self.send_response(200)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_OPTIONS(self):
        self.visits.append(("OPTIONS", self.path))
        self.send_response(204)
        self.end_headers()


class DiscoveryScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        Handler.visits.clear()
        self.client = ScopedClient(self.url, delay=0)
        self.addCleanup(self.client.session.close)

    def test_redirect_to_previously_scanned_resource_is_not_analyzed_twice(self):
        resources=list(Crawler(self.client,max_pages=3,include_urls=["/hidden","/redirect"]).crawl())
        self.assertEqual(sum(r.url==self.url+"/hidden" for r in resources),1)
        self.assertEqual(len(resources),2)

    def config(self, config):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "active.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            return load_config(str(path), self.client)

    def test_styles_frames_and_maps_respect_depth(self):
        resources = list(Crawler(self.client, max_depth=1).crawl())
        paths = {r.url.removeprefix(self.url) for r in resources}
        self.assertEqual(paths, {"/", "/style.css", "/theme.css", "/theme.map", "/frame"})
        self.assertNotIn(("GET", "/deep"), Handler.visits)

    def test_sitemap_indexes_share_budget_and_robots(self):
        crawler = Crawler(self.client, max_depth=0, discover_sitemaps=True)
        resources = list(crawler.crawl())
        self.assertIn(self.url + "/hidden", {r.url for r in resources})
        self.assertNotIn(("GET", "/blocked"), Handler.visits)
        self.assertEqual(crawler.attempts, len(Handler.visits) - 1)
        Handler.visits.clear()
        crawler = Crawler(self.client, max_pages=2, discover_sitemaps=True)
        list(crawler.crawl())
        self.assertEqual(crawler.attempts, 2)
        self.assertEqual(len(Handler.visits), 3)

    def test_sitemap_xml_entities_are_rejected(self):
        crawler = Crawler(self.client, max_pages=10, discover_sitemaps=True)
        crawler.sitemaps = [self.url + "/unsafe.xml"]
        with patch.object(crawler, "load_robots"):
            list(crawler.crawl())
        self.assertTrue(any(f.title == "Unsafe sitemap XML skipped" for f in self.client.errors))

    def test_utf16_sitemap_entities_are_rejected(self):
        response = requests.Response()
        response.status_code = 200
        response.url = self.url + "/map.xml"
        response.headers["Content-Type"] = "application/xml"
        response._content = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE urlset [<!ENTITY x "fixture">]><urlset>&x;</urlset>'.encode("utf-16")
        crawler = Crawler(self.client, discover_sitemaps=True)
        crawler.sitemaps = [self.client.target]
        with patch.object(crawler, "load_robots"), patch.object(self.client, "get", return_value=response):
            list(crawler.crawl())
        self.assertTrue(any(f.title == "Unsafe sitemap XML skipped" for f in self.client.errors))

    def test_http_contract_methods_and_redacted_results(self):
        config = self.config({"environment": "staging", "http_checks": [
            {"path": "/health", "method": "HEAD", "expected_status": [200], "required_headers": ["X-Content-Type-Options"]},
            {"path": "/api", "method": "OPTIONS", "expected_status": [204]},
            {"path": "/private?token=sensitive", "method": "GET", "expected_status": [403], "required_headers": ["Content-Security-Policy"]},
        ]})
        results = run_active(self.client, config, lambda url: self.client.allowed(url))
        self.assertEqual([f.severity for f in results], ["Info", "Info", "Warning"])
        self.assertIn(("HEAD", "/health"), Handler.visits)
        self.assertIn(("OPTIONS", "/api"), Handler.visits)
        self.assertNotIn("sensitive", str(results))
        self.assertNotIn("nosniff", str(results))

    def test_active_checks_respect_robots_and_refuse_redirects(self):
        crawler = Crawler(self.client)
        crawler.load_robots()
        config = self.config({"environment": "local", "http_checks": [
            {"path": "/blocked", "method": "HEAD", "expected_status": [200]},
            {"path": "/redirect", "method": "GET", "expected_status": [200]},
        ]})
        self.assertEqual(run_active(self.client, config, crawler.permitted), [])
        self.assertNotIn(("HEAD", "/blocked"), Handler.visits)
        self.assertNotIn(("GET", "/hidden"), Handler.visits)

    def test_invalid_active_config_never_sends_requests(self):
        checks = [
            {"path": "/", "method": "DELETE", "expected_status": [200]},
            {"path": "/", "method": [], "expected_status": [200]},
            {"path": "https://outside.invalid/", "expected_status": [200]},
            {"path": "/", "expected_status": [True]},
            {"path": "/", "expected_status": [200], "required_headers": ["bad\r\nheader"]},
        ]
        for check in checks:
            with self.subTest(check=check), self.assertRaises(ValueError):
                self.config({"environment": "staging", "http_checks": [check]})
        with self.assertRaises(ValueError):
            self.config({"environment": "production", "http_checks": [checks[0]]})
        with self.assertRaises(ValueError):
            self.config({"environment": "local", "http_checks": [{"path": "/", "expected_status": [200]}] * 11})
        self.assertEqual(Handler.visits, [])

    def test_exclusion_canonicalization_and_boundary(self):
        for host in ("google.com", "api.google.com", "GOOGLE.COM.", "%67oogle.com", "google\u3002com"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                ScopedClient("https://" + host)
        self.assertFalse(blocked("https://notgoogle.com/"))
        self.assertFalse(blocked("https://google.com.attacker.invalid/"))
        with self.assertRaises(ValueError):
            ScopedClient(self.url, exclude_domains=["127.0.0.1"])

    def test_exclusion_precedes_tls_and_network(self):
        args = parser().parse_args(["--url", "https://google.com", "--confirm-authorized"])
        with patch("gilbrt.cli.analyze_tls") as tls, patch("requests.Session.get") as get:
            with self.assertRaises(ValueError):
                run_audit(args, {"tls"})
        tls.assert_not_called()
        get.assert_not_called()

    def test_cli_explains_exclusion_without_requests(self):
        output = io.StringIO()
        with redirect_stdout(output), patch("requests.Session.get") as get:
            result = main(["--url", "https://github.com", "--confirm-authorized"])
        self.assertEqual(result, 1)
        self.assertIn("do-not-test", output.getvalue())
        get.assert_not_called()
