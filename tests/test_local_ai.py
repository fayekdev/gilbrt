"""Local-model integration checks using a loopback Ollama fixture, not real inference."""

import json
import threading
import unittest
from unittest.mock import patch
import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gilbrt.local_ai import LocalAnalyzer, chunks, loopback_url, ground_quote, control_context
from gilbrt.cli import main


class OllamaFixture(BaseHTTPRequestHandler):
    """Simulate model metadata and source-grounded/hallucinated generation output."""

    remote = False
    requests_seen: list[dict] = []
    malformed = False

    def log_message(self, *_args) -> None:
        """Suppress fixture logs."""

    def send_json(self, value: dict) -> None:
        """Return bounded JSON."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def do_GET(self) -> None:
        """Return local or cloud-backed model metadata."""
        if self.path == "/robots.txt":
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/site":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<script>if(x === "fixture-ai-code")openGate();</script>')
            return
        self.send_json({"models": [{"name": "test-coder:1b", "size": 1000,
                        "remote_host": "https://remote.invalid" if self.remote else ""}]})

    def do_POST(self) -> None:
        """Generate candidates including one fabricated value that must be rejected."""
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.requests_seen.append(payload)
        output = {"findings": [
            {"kind": "admin_gate", "quote": 'x === "fixture-ai-code"', "value": "fixture-ai-code"},
            {"kind": "password", "quote": 'x === "fixture-ai-code"', "value": "invented-secret"},
            {"kind": "access_code", "quote": 'x === "not-in-source"', "value": "not-in-source"},
        ]}
        if 'const heading = "Welcome"' in payload.get("prompt", ""):
            output = {"findings": [{"kind": "password", "quote": '"Welcome"', "value": "Welcome"}]}
        self.send_json({"done": True, "response": "not JSON" if self.malformed else json.dumps(output)})


class LocalAITests(unittest.TestCase):
    """Check locality, source grounding, bounded work and failure handling."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), OllamaFixture)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self) -> None:
        OllamaFixture.remote = False
        OllamaFixture.malformed = False
        OllamaFixture.requests_seen.clear()

    def test_local_source_grounding_and_redaction(self) -> None:
        analyzer = LocalAnalyzer("test-coder:1b", self.url)
        revealed = []
        try:
            findings = analyzer.analyze('if (x === "fixture-ai-code") openGate();', "https://authorized.invalid/",
                                       on_secret=lambda finding, value: revealed.append(value))
            self.assertEqual(len(findings), 1)
            self.assertEqual(revealed, ["fixture-ai-code"])
            self.assertNotIn("fixture-ai-code", str(findings))
            self.assertNotIn("invented-secret", str(findings))
            self.assertFalse(OllamaFixture.requests_seen[0]["stream"])
            self.assertIsInstance(OllamaFixture.requests_seen[0]["format"], dict)
        finally:
            analyzer.close()

    def test_remote_model_is_rejected_before_source_submission(self) -> None:
        OllamaFixture.remote = True
        analyzer = LocalAnalyzer("test-coder:1b", self.url)
        try:
            findings = analyzer.analyze('x === "fixture-ai-code"', "https://authorized.invalid/")
            self.assertTrue(analyzer.failed)
            self.assertEqual(findings[0].category, "Coverage")
            self.assertFalse(OllamaFixture.requests_seen)
        finally:
            analyzer.close()

    def test_budget_and_html_script_extraction(self) -> None:
        analyzer = LocalAnalyzer("test-coder:1b", self.url, max_chunks=1)
        try:
            body = '<img src="data:image/png;base64,' + 'A' * 5000 + '"><script>if(x === "fixture-ai-code")openGate();' + ' ' * 5000 + '</script>'
            analyzer.analyze(body, "https://authorized.invalid/", html=True)
            self.assertEqual(analyzer.used, 1)
            self.assertTrue(analyzer.skipped)
            self.assertNotIn("data:image", OllamaFixture.requests_seen[0]["prompt"])
        finally:
            analyzer.close()

    def test_bad_json_is_coverage_gap_without_raw_model_text(self) -> None:
        OllamaFixture.malformed = True
        analyzer = LocalAnalyzer("test-coder:1b", self.url)
        try:
            findings = analyzer.analyze('x === "fixture-ai-code"', "https://authorized.invalid/")
            self.assertTrue(analyzer.failed)
            self.assertEqual(findings[0].category, "Coverage")
            self.assertNotIn("not JSON", str(findings))
            self.assertEqual(analyzer.used, 1)
            self.assertEqual(analyzer.completed, 0)
        finally:
            analyzer.close()

    def test_ordinary_ui_literal_is_rejected_despite_model_claim(self) -> None:
        analyzer = LocalAnalyzer("test-coder:1b", self.url)
        try:
            findings = analyzer.analyze('const heading = "Welcome"; console.log(heading);', "https://authorized.invalid/")
            self.assertEqual(findings, [])
            self.assertEqual(analyzer.completed, 1)
        finally:
            analyzer.close()

    def test_only_loopback_endpoints(self) -> None:
        self.assertEqual(loopback_url("http://127.0.0.1:11434/"), "http://127.0.0.1:11434")
        for url in ("http://remote.invalid", "http://localhost:11434", "http://127.0.0.1:11434/api", "http://user:pass@127.0.0.1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                loopback_url(url)

    def test_control_context_requires_evidence_in_the_actual_comparison(self) -> None:
        for source, quote, value in [
            ('const passwordLabel="Password"; if(theme === "dark")render();', 'theme === "dark"', "dark"),
            ('if(response.code === 1000)close();', 'response.code === 1000', "1000"),
            ('const secret="YOUR_SECRET";', 'secret="YOUR_SECRET"', "YOUR_SECRET"),
        ]:
            with self.subTest(source=source):
                self.assertFalse(control_context(source, quote, source.index(quote), value))
        source = 'if(x === "actual-gate")openGate();'
        quote = 'x === "actual-gate"'
        self.assertTrue(control_context(source, quote, source.index(quote), "actual-gate"))

    def test_model_password_claim_cannot_override_syntax_classification(self) -> None:
        analyzer = LocalAnalyzer("test-coder:1b", self.url)
        source = 'const passwordLabel="Password"; if(code === "4827")allow();'
        output = {"done": True, "response": json.dumps({"findings": [
            {"kind": "password", "quote": 'code === "4827"', "value": "4827"},
            {"kind": "password", "quote": 'passwordLabel="Password"', "value": "Password"},
        ]})}
        try:
            with patch.object(analyzer, "verify_model"), patch.object(analyzer, "request", return_value=output):
                findings = analyzer.analyze(source, "https://authorized.invalid/")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].severity, "Warning")
        finally:
            analyzer.close()

    def test_keyword_windows_are_prioritized(self) -> None:
        text = "A" * 20000 + 'const adminCode="fixture-ai-code";'
        first, offset = next(chunks(text))
        self.assertGreater(offset, 0)
        self.assertIn("adminCode", first)

    def test_equivalent_quote_style_is_grounded_but_invented_logic_is_not(self) -> None:
        source = 'if (v === "synthetic-code") allow();'
        grounded = ground_quote(source, "v=== 'synthetic-code'")
        self.assertIsNotNone(grounded)
        self.assertEqual(grounded[0], 'v === "synthetic-code"')
        self.assertIsNone(ground_quote(source, "v !== 'synthetic-code'"))
        self.assertIsNone(ground_quote(source, "admin === 'synthetic-code'"))
        self.assertIsNone(ground_quote('// v === "synthetic-code"', "v === 'synthetic-code'"))

    def test_cli_local_model_pipeline_and_report_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "audit.json"
            terminal = io.StringIO()
            with redirect_stdout(terminal):
                result = main(["--url", self.url + "/site", "--confirm-authorized", "--rate-limit", "0",
                               "--search", "access-codes", "--local-model", "test-coder:1b", "--ollama-url", self.url,
                               "--output", str(filename)])
            self.assertEqual(result, 0)
            report = json.loads(filename.read_text())
            self.assertEqual(report["metadata"]["local_ai"]["chunks_analyzed"], 1)
            self.assertEqual(report["metadata"]["local_ai"]["chunks_submitted"], 1)
            self.assertEqual(sum(f["category"] in {"Access code", "Local AI"} for f in report["findings"]), 1)
            self.assertEqual(report["metadata"]["local_ai"]["duplicate_candidates_omitted"], 1)
            self.assertNotIn("fixture-ai-code", filename.read_text())
            self.assertNotIn("fixture-ai-code", terminal.getvalue())


if __name__ == "__main__":
    unittest.main()
