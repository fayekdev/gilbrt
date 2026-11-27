"""Coverage failures must not look like successful password inspections."""

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gilbrt.cli import main
from gilbrt.models import Finding
from gilbrt.reporter import assess_findings, render_report


class ReportAssessmentTests(unittest.TestCase):
    def finding(self, category, title="Observation"):
        return Finding("Warning", category, title, "resource", "redacted evidence", "Review")

    def test_header_only_is_not_a_credential_detection(self):
        findings = [self.finding("Headers"), self.finding("TLS")]
        metadata = {"resources_scanned": 3, "search_categories": ["passwords", "headers"]}
        result = assess_findings(findings, metadata)
        self.assertEqual(result["credential_candidates"], 0)
        self.assertEqual(result["configuration_observations"], 2)
        self.assertIn("inconclusive", result["summary"])
        document = json.loads(render_report(findings, "json", metadata))
        self.assertEqual(len(document["findings"]), 2)
        for fmt in ("html", "ai"):
            self.assertIn("No credential candidates", render_report(findings, fmt, metadata))

    def test_zero_source_overrides_tls_observations(self):
        findings = [self.finding("TLS"), self.finding("Coverage", "Resource size exceeded")]
        result = assess_findings(findings, {"resources_scanned": 0})
        self.assertEqual(result["status"], "source_scan_failed")
        self.assertIn("could not run", result["summary"])
        self.assertEqual(result["configuration_observations"], 1)

    def test_partial_and_unknown_coverage_are_explicit(self):
        result = assess_findings([self.finding("Password"), self.finding("Coverage")], {"resources_scanned": 1})
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["credential_candidates"], 1)
        self.assertIn("not validated", result["summary"])
        self.assertEqual(assess_findings([], {})["status"], "unknown")
        self.assertIn("not selected", assess_findings([], {"resources_scanned": 2, "search_categories": ["headers"]})["summary"])

    def test_oversized_page_exits_failed_then_retests_with_explicit_limit(self):
        body = ('<div>' + 'x' * (1024 * 1024) + '</div><script>const adminPassword="limit-fixture-8391";</script>').encode()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                if self.path == "/robots.txt":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "report.json"
                args = ["--url", f"http://127.0.0.1:{server.server_port}", "--confirm-authorized",
                        "--search", "passwords", "--rate-limit", "0", "--output", str(output)]
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args + ["--max-resource-mb", "1"]), 1)
                failed = json.loads(output.read_text())
                self.assertEqual(failed["assessment"]["status"], "source_scan_failed")
                self.assertEqual(failed["metadata"]["resources_scanned"], 0)
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(main(args + ["--max-resource-mb", "2"]), 0)
                success = json.loads(output.read_text())
                self.assertEqual(success["assessment"]["credential_candidates"], 1)
                self.assertNotIn("limit-fixture-8391", output.read_text())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
