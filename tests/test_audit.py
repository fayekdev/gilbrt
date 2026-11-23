"""Offline unit and local HTTP integration checks for scope, redaction and isolation."""

import json
import os
import re
import ssl
import io
from contextlib import redirect_stdout, redirect_stderr
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from gilbrt.active import load_config, run_active
from gilbrt.breach_check import check_breaches
from gilbrt.cli import main, nonnegative
from gilbrt.crawler import Crawler, ScopedClient
from gilbrt.headers import analyze_headers, analyze_tls
from gilbrt.models import Finding
from gilbrt.reporter import export
from gilbrt.scanner import entropy, safe_url, scan

SECRET = "AKIA" + "A" * 16
MARKER = "GILBRT_SYNTHETIC_TEST_MARKER_128"


class Handler(BaseHTTPRequestHandler):
    """A staging fixture with robots, links, redirects and a private record."""

    visits: list[str] = []

    def log_message(self, *_args) -> None:
        """Keep fixture access logs quiet."""

    def do_GET(self) -> None:
        """Serve deterministic content without exposing test credentials in logs."""
        self.visits.append(self.path)
        status, kind, body = 200, "text/html", ""
        if self.path == "/robots.txt":
            kind, body = "text/plain", "User-agent: *\nDisallow: /blocked\n"
        elif self.path == "/":
            body = '<a href="/child">child</a><a href="/blocked">blocked</a><script src="/app.js"></script><a href="/child">duplicate</a>'
        elif self.path == "/child":
            body = '<a href="/grandchild">grandchild</a>'
        elif self.path == "/app.js":
            kind, body = "application/javascript", '// TODO internal\nconst key="' + SECRET + '";\n//# sourceMappingURL=/app.js.map'
        elif self.path == "/app.js.map":
            kind, body = "application/json", json.dumps({"sourcesContent": [SECRET]})
        elif self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/outside")
            self.end_headers()
            return
        elif self.path == "/robots-redirect":
            self.send_response(302)
            self.send_header("Location", "/blocked")
            self.end_headers()
            return
        elif self.path == "/private":
            kind = "application/json"
            if self.headers.get("Authorization") == "Bearer owner-test-token":
                body = json.dumps({"content": MARKER})
            else:
                status, body = 403, '{}'
        elif self.path == "/public-synthetic":
            kind, body = "application/json", json.dumps({"content": MARKER})
        elif self.path == "/visible-config.json":
            kind, body = "application/json", '{"db_password":"hunter2"}'
        elif self.path == "/access-gate":
            body = '<script>if (accessCode === "fixture-gate") allow();</script>'
        elif self.path == "/large-gate":
            body = '<div>' + 'A' * (2 * 1024 * 1024) + '</div><script>if(accessCode === "large-gate-fixture")allow();</script>'
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self) -> None:
        """Simulate a model disclosing only the synthetic system-message canary."""
        self.visits.append(self.path)
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        canary = re.search(r"GILBRT_[a-f0-9]{32}", body["messages"][0]["content"]).group()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"choices": [{"message": {"content": canary}}]}).encode())


class AuditTests(unittest.TestCase):
    """Exercise security boundaries using a loopback-only HTTP server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self) -> None:
        Handler.visits.clear()
        self.client = ScopedClient(self.url, delay=0)

    def tearDown(self) -> None:
        self.client.session.close()

    def test_crawl_depth_robots_scripts_and_source_maps(self) -> None:
        resources = list(Crawler(self.client, max_depth=1).crawl())
        self.assertEqual(len(resources), 4)
        self.assertNotIn("/blocked", Handler.visits)
        self.assertNotIn("/grandchild", Handler.visits)
        self.assertEqual(Handler.visits.count("/child"), 1)
        self.assertIn("/app.js.map", Handler.visits)

    def test_resource_cap(self) -> None:
        self.assertEqual(len(list(Crawler(self.client, max_pages=1).crawl())), 1)

    def test_large_source_is_scanned_and_configured_cap_is_enforced(self) -> None:
        resources = list(Crawler(self.client, max_pages=2, include_urls=["/large-gate"]).crawl())
        gate = next(r for r in resources if r.url.endswith("/large-gate"))
        findings = scan(gate.body, gate.url, html=True, checks={"access-codes"})
        self.assertTrue(any(f.category == "Access code" for f in findings))
        self.client.max_resource_bytes = 1024 * 1024
        self.assertIsNone(self.client.get(self.url + "/large-gate"))
        self.assertTrue(any("byte limit" in f.title for f in self.client.errors))

    def test_redirect_scope_and_robots_checked_before_request(self) -> None:
        crawler = Crawler(self.client)
        crawler.load_robots()
        self.assertIsNone(self.client.get(self.url + "/external-redirect", crawler.permitted))
        self.assertIsNone(self.client.get(self.url + "/robots-redirect", crawler.permitted))
        self.assertNotIn("/blocked", Handler.visits)

    def test_static_redaction_all_exports(self) -> None:
        body = '<!-- password=hunter2 TODO internal -->\n<script>const api_key="' + SECRET + '";</script>'
        findings = scan(body, self.url + "/private/path?token=topsecret", html=True)
        self.assertTrue(any(f.category == "Secret" for f in findings))
        for fmt in ("json", "csv", "html", "ai"):
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / ("audit." + fmt)
                export(findings, str(output), fmt, {})
                report = output.read_text(encoding="utf-8-sig")
                for private in (SECRET, "hunter2", "topsecret", "/private/path"):
                    self.assertNotIn(private, report)

    def test_low_entropy_passwords_and_html_fields(self) -> None:
        body = '''<script>const dbPassword = "hunter2"; const PASSWORD='simple';</script>
        <input type="password" value="easy123">
        <textarea name="password">short</textarea><div data-password="123456"></div>
        <p><b>Password:</b> visible123</p><table><tr><td>Password</td><td>table123</td></tr></table>'''
        revealed = []
        findings = scan(body, self.url, html=True, checks={"passwords"},
                        on_secret=lambda finding, value: revealed.append(value))
        for value in ("hunter2", "simple", "easy123", "short", "123456", "visible123", "table123"):
            self.assertIn(value, revealed)
            self.assertNotIn(value, str(findings))
        self.assertTrue(all(f.category == "Password" for f in findings))

    def test_search_categories_exclude_unselected_detectors(self) -> None:
        text = 'const password="hunter2"; const key="' + SECRET + '"; // TODO internal'
        passwords = scan(text, self.url, checks={"passwords"})
        self.assertEqual(len(passwords), 1)
        self.assertEqual(passwords[0].category, "Password")
        self.assertFalse(scan(text, self.url, checks=set()))
        self.assertTrue(all(f.category == "Secret" for f in scan(text, self.url, checks={"api-keys"})))

    def test_decoded_source_map_passwords(self) -> None:
        body = json.dumps({"sourcesContent": ['const password="hunter2";']})
        findings = scan(body, self.url, checks={"passwords"})
        self.assertTrue(any("Source-map source 0" in f.evidence for f in findings))
        self.assertNotIn("hunter2", str(findings))

    def test_explicit_same_origin_extra_resource(self) -> None:
        resources = list(Crawler(self.client, max_depth=0, include_urls=["/visible-config.json"]).crawl())
        self.assertTrue(any(r.url.endswith("/visible-config.json") for r in resources))
        with self.assertRaises(ValueError):
            Crawler(self.client, include_urls=["https://elsewhere.invalid/"])

    def test_cli_reveal_is_local_and_exports_stay_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "passwords.json"
            for reveal in (False, True):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = main(["--url", self.url + "/visible-config.json", "--confirm-authorized", "--rate-limit", "0",
                                   "--search", "passwords", "--output", str(filename)] + (["--show-secrets"] if reveal else []))
                self.assertEqual(result, 0)
                self.assertEqual("hunter2" in output.getvalue(), reveal)
                self.assertEqual("REDACTED" in output.getvalue(), not reveal)
                self.assertNotIn("hunter2", filename.read_text())
                document = json.loads(filename.read_text())
                self.assertEqual(document["metadata"]["search_categories"], ["passwords"])
                self.assertEqual(document["findings"][0]["severity"], "Critical")

    def test_cli_detects_inline_access_gate_and_redacts_ai_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "gate-report.md"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--url", self.url + "/access-gate", "--confirm-authorized", "--rate-limit", "0",
                               "--search", "access-codes", "--show-secrets", "--format", "ai", "--output", str(filename)])
            self.assertEqual(result, 0)
            self.assertIn("fixture-gate", output.getvalue())
            report = filename.read_text(encoding="utf-8")
            self.assertIn("Hardcoded access code comparison", report)
            self.assertNotIn("fixture-gate", report)

    def test_low_memory_ai_falls_back_to_selected_static_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "low-memory.json"
            with patch("gilbrt.cli.BundledAnalyzer", side_effect=MemoryError), redirect_stdout(io.StringIO()):
                result = main(["--url", self.url + "/visible-config.json", "--confirm-authorized", "--rate-limit", "0",
                               "--search", "passwords", "--local-model", "bundled", "--output", str(filename)])
            self.assertEqual(result, 0)
            report = json.loads(filename.read_text())
            self.assertTrue(report["metadata"]["local_ai"]["requested"])
            self.assertFalse(report["metadata"]["local_ai"]["enabled"])
            self.assertTrue(any(f["category"] == "Password" for f in report["findings"]))
            self.assertTrue(any("low available memory" in f["title"] for f in report["findings"]))

    def test_cli_interactive_menu(self) -> None:
        output = io.StringIO()
        with patch("gilbrt.cli.sys.stdin.isatty", return_value=True), \
             patch("gilbrt.cli.Prompt.ask", side_effect=[self.url + "/visible-config.json"]), \
             patch("gilbrt.cli.select_checks", return_value={"passwords"}), \
             patch("gilbrt.cli.Confirm.ask", return_value=False), \
             patch("gilbrt.cli.print_summary") as summary, redirect_stdout(output):
            self.assertEqual(main(["--interactive", "--confirm-authorized", "--rate-limit", "0"]), 0)
        self.assertTrue(any(f.category == "Password" for f in summary.call_args.args[0]))
        self.assertNotIn("hunter2", output.getvalue())

    def test_command_only_wizard_exports_full_ai_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "ai-report.md"
            with patch("gilbrt.cli.sys.stdin.isatty", return_value=True), \
                 patch("gilbrt.cli.Prompt.ask", side_effect=[self.url + "/visible-config.json", "ai", str(filename)]), \
                 patch("gilbrt.cli.select_checks", return_value={"passwords"}), \
                 patch("gilbrt.cli.Confirm.ask", side_effect=[True, False, False, True]), \
                 patch("gilbrt.crawler.ScopedClient.pace"), redirect_stdout(io.StringIO()):
                self.assertEqual(main([]), 0)
            report = filename.read_text(encoding="utf-8")
            for required in ("AI review report", "Potential exposed password", '"passwords"', '"resource_inventory"',
                             "Evidence handling", '"summary"', '"resources_scanned": 1'):
                self.assertIn(required, report)
            self.assertNotIn("hunter2", report)

    def test_wizard_declined_authorization_makes_no_requests(self) -> None:
        with patch("gilbrt.cli.sys.stdin.isatty", return_value=True), \
             patch("gilbrt.cli.Prompt.ask", side_effect=[self.url]), \
             patch("gilbrt.cli.select_checks", return_value={"passwords"}), \
             patch("gilbrt.cli.Confirm.ask", return_value=False), \
             patch("gilbrt.cli.ScopedClient") as client, redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 1)
            client.assert_not_called()

    def test_wizard_interrupt_makes_no_requests(self) -> None:
        with patch("gilbrt.cli.sys.stdin.isatty", return_value=True), \
             patch("gilbrt.cli.Prompt.ask", side_effect=KeyboardInterrupt), \
             patch("gilbrt.cli.ScopedClient") as client, redirect_stdout(io.StringIO()):
            self.assertEqual(main([]), 130)
            client.assert_not_called()

    def test_ai_export_preserves_all_findings_and_fences_untrusted_text(self) -> None:
        findings = [Finding("Warning", "Test", "Candidate", safe_url(self.url), "```\nUntrusted evidence", "Review"),
                    Finding("Info", "Coverage", "Skipped resource", safe_url(self.url), "Robots denied", "Review scope")]
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "ai.md"
            export(findings, str(filename), "ai", {"resources_scanned": 1})
            report = filename.read_text(encoding="utf-8")
            self.assertIn("````json", report)
            data = json.loads(report.split("````json\n", 1)[1].split("\n````", 1)[0])
            self.assertEqual(len(data["findings"]), 2)
            self.assertEqual(data["summary"], {"Critical": 0, "Warning": 1, "Info": 1})

    def test_duplicate_scheme_rejected_before_network(self) -> None:
        with redirect_stderr(io.StringIO()), patch("gilbrt.cli.ScopedClient") as client:
            with self.assertRaises(SystemExit) as result:
                main(["--url", "https://https://authorized.invalid/", "--confirm-authorized"])
            self.assertEqual(result.exception.code, 2)
            client.assert_not_called()

    def test_entropy_candidates_and_short_secret_masking(self) -> None:
        self.assertEqual(entropy("aaaa"), 0)
        findings = scan('const secret="aB3!dE6@hI9#kL2$mN5%pQ8&";', self.url)
        self.assertTrue(any("entropy" in f.title for f in findings))

    def test_trailing_js_comments_and_literal_urls(self) -> None:
        findings = scan('const url="https://example.invalid/internal"; // TODO debug\n', self.url)
        comments = [f for f in findings if f.category == "Comment"]
        self.assertEqual(len(comments), 1)
        self.assertIn("debug, todo", comments[0].evidence)
        self.assertNotIn("internal", comments[0].evidence)

    def test_cookie_and_header_analysis(self) -> None:
        response = requests.Response()
        response.url = self.url
        response.headers["Set-Cookie"] = "session=very-private; SameSite=None"
        response.headers["Content-Security-Policy"] = "script-src * 'unsafe-inline'"
        response.headers["X-Content-Type-Options"] = "wrong"
        findings = analyze_headers(response)
        self.assertTrue(any("SameSite=None" in f.title for f in findings))
        self.assertTrue(any("Permissive" in f.title for f in findings))
        self.assertNotIn("very-private", str(findings))

    def test_isolation_protected_and_exposed_synthetic_records(self) -> None:
        config = {"isolation": [{"path": "/private", "marker": MARKER,
                               "owner_token_env": "OWNER", "other_token_env": "OTHER"}]}
        with patch.dict(os.environ, {"OWNER": "owner-test-token", "OTHER": "other-test-token"}):
            protected = run_active(self.client, config, self.client.allowed)
            self.assertFalse(any(f.severity == "Critical" for f in protected))
            config["isolation"][0]["path"] = "/public-synthetic"
            exposed = run_active(self.client, config, self.client.allowed)
            self.assertEqual(sum(f.severity == "Critical" for f in exposed), 2)
            self.assertNotIn(MARKER, str(exposed))

    def test_config_rejects_out_of_scope_and_production(self) -> None:
        for config in ({"environment": "production"}, {"environment": "staging", "isolation": [{"path": "http://elsewhere.invalid/"}]}):
            with tempfile.TemporaryDirectory() as directory:
                filename = Path(directory) / "config.json"
                filename.write_text(json.dumps(config), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_config(str(filename), self.client)

    def test_prompt_canary_probe_withholds_generated_content(self) -> None:
        config = {"prompts": [{"path": "/v1/chat/completions", "model": "synthetic-model", "token_env": "AI_TOKEN"}]}
        with patch.dict(os.environ, {"AI_TOKEN": "test-only-credential"}):
            findings = run_active(self.client, config, self.client.allowed)
        self.assertEqual(findings[0].title, "Synthetic canary disclosed")
        self.assertNotIn("GILBRT_", str(findings))
        self.assertNotIn("test-only-credential", str(findings))

    def test_tls_certificate_failure_is_not_silently_ignored(self) -> None:
        with patch("gilbrt.headers.socket.create_connection", side_effect=ssl.SSLCertVerificationError()):
            findings = analyze_tls("https://authorized.invalid/")
        self.assertEqual(findings[0].severity, "Critical")

    def test_rate_limit_between_request_starts(self) -> None:
        self.client.delay = 1
        with patch("gilbrt.crawler.time.monotonic", side_effect=[10, 10.25, 11]), patch("gilbrt.crawler.time.sleep") as sleep:
            self.client.pace()
            self.client.pace()
        sleep.assert_called_once_with(0.75)

    def test_hibp_exact_catalogue_match_without_email_query(self) -> None:
        session = MagicMock()
        response = MagicMock()
        response.status_code = 200
        response.iter_content.return_value = [json.dumps([
            {"Domain": "authorized.invalid", "BreachDate": "2020-01-01", "DataClasses": ["Passwords"]},
            {"Domain": "other.invalid", "BreachDate": "2021-01-01", "DataClasses": []}
        ]).encode()]
        session.get.return_value.__enter__.return_value = response
        with patch("gilbrt.breach_check.requests.Session") as factory:
            factory.return_value.__enter__.return_value = session
            findings = check_breaches("https://authorized.invalid/", "test-key")
        self.assertEqual(len(findings), 1)
        self.assertIn("2020-01-01", findings[0].evidence)
        self.assertIn("Passwords", findings[0].evidence)
        self.assertEqual(session.get.call_args.args[0], "https://haveibeenpwned.com/api/v3/breaches")
        self.assertFalse(session.get.call_args.kwargs["allow_redirects"])

    def test_html_and_csv_injection_escaped(self) -> None:
        finding = Finding("Info", "Test", "=1+1", safe_url(self.url), "<script>alert(1)</script>", "Review")
        with tempfile.TemporaryDirectory() as directory:
            csv_path, html_path = Path(directory) / "a.csv", Path(directory) / "a.html"
            export([finding], str(csv_path), "csv", {})
            export([finding], str(html_path), "html", {})
            self.assertIn("'=1+1", csv_path.read_text(encoding="utf-8-sig"))
            self.assertNotIn("<script>", html_path.read_text())

    def test_cli_requires_authorization_before_network(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--url", self.url])
        self.assertEqual(Handler.visits, [])

    def test_cli_local_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            self.assertEqual(main(["--url", self.url, "--confirm-authorized", "--rate-limit", "0",
                                   "--max-depth", "1", "--output", str(filename)]), 0)
            report = json.loads(filename.read_text())
            self.assertEqual(report["metadata"]["resources_scanned"], 4)
            self.assertNotIn(SECRET, filename.read_text())


if __name__ == "__main__":
    unittest.main()
