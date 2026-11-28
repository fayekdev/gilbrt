"""Validate benchmark integrity independently of scanner accuracy improvements."""

import io
import json
import os
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from gilbrt.models import Finding
from gilbrt.scanner import safe_url
from scripts.benchmark_lab import Case, Lab, TEST_ENV, active_config, digest, make_handler, run_profile, score_content, score_contracts


class BenchmarkLabTests(unittest.TestCase):
    origin = "http://127.0.0.1:12345"

    def finding(self, category="Password", path="/case.js", title="Candidate"):
        return Finding("Warning", category, title, safe_url(self.origin+path), "redacted", "review")

    def score(self, cases, findings, visible=None, paths=("/case.js",)):
        return score_content(cases, findings, visible or {}, {"resource_inventory": [{"resource": safe_url(self.origin+p)} for p in paths]}, self.origin)

    def test_seed_changes_values_paths_and_padding_without_changing_cases(self):
        first, same, other = Lab(17), Lab(17), Lab(29)
        self.assertEqual(first.cases, same.cases)
        self.assertEqual(first.routes, same.routes)
        self.assertEqual([c.name for c in first.cases], [c.name for c in other.cases])
        self.assertNotEqual([c.path for c in first.cases], [c.path for c in other.cases])
        self.assertNotEqual([c.fingerprint for c in first.cases], [c.fingerprint for c in other.cases])
        self.assertTrue(all(path.startswith("/") for path in first.routes))

    def test_full_value_category_and_resource_are_required(self):
        case = Case("exact", "/case.js", "Password", digest("complete-secret-8931"))
        for value, category, path in [("complete", "Password", "/case.js"),
                                      ("complete-secret-8931", "Secret", "/case.js"),
                                      ("complete-secret-8931", "Password", "/other.js")]:
            finding = self.finding(category, path)
            self.assertEqual(self.score([case], [finding], {id(finding):value})["counts"]["FN"], 1)
        finding = self.finding()
        self.assertEqual(self.score([case], [finding], {id(finding):"complete-secret-8931"})["counts"]["TP"], 1)
        self.assertEqual(self.score([case], [finding], {id(finding):"complete-secret-8931"}, paths=())["counts"]["FN"], 1)

    def test_duplicates_and_headers_cannot_inflate_content_score(self):
        case = Case("exact", "/case.js", "Password", digest("complete-secret-8931"))
        one, two = self.finding(), self.finding()
        result = self.score([case], [one,two], {id(one):"complete-secret-8931",id(two):"complete-secret-8931"})
        self.assertEqual(result["counts"]["TP"], 1)
        header = self.finding("Headers")
        self.assertEqual(self.score([case], [header], {id(header):"complete-secret-8931"})["counts"]["TP"], 0)

    def test_unreached_controls_never_count_as_true_negatives(self):
        cases = [Case("positive", "/case.js", "Password", digest("example-secret")), Case("negative", "/negative.js", None)]
        result = self.score(cases, [], paths=())
        self.assertEqual(result["counts"]["FN"], 1)
        self.assertEqual(result["counts"]["TN"], 0)
        self.assertEqual(result["counts"]["UNREACHED_CONTROL"], 1)
        self.assertEqual(result["cases"][0]["miss_kind"], "discovery")

    def test_unexecuted_contracts_do_not_pass(self):
        result = score_contracts(Lab(17), [], self.origin, [])
        self.assertTrue(all(c["passed"] is None for c in result["headers"]+result["configured_active_probes"]))

    def test_resource_graph_active_controls_and_report_redaction(self):
        lab = Lab(17)
        trap = ThreadingHTTPServer(("127.0.0.1",0), make_handler(lab,trap=True))
        server = ThreadingHTTPServer(("127.0.0.1",0), make_handler(lab))
        server.trap_origin = f"http://127.0.0.1:{trap.server_port}"
        origin = f"http://127.0.0.1:{server.server_port}"
        threads = [threading.Thread(target=s.serve_forever,daemon=True) for s in (trap,server)]
        for thread in threads:
            thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, TEST_ENV), redirect_stdout(io.StringIO()):
                destination = Path(directory)
                (destination/"active-config.json").write_text(json.dumps(active_config()),encoding="utf-8")
                full = run_profile(lab,origin,destination,"full")
                self.assertTrue(all(full["contracts"]["boundaries"].values()))
                self.assertTrue(all(c["passed"] for c in full["contracts"]["headers"]+full["contracts"]["configured_active_probes"]))
                self.assertFalse(full["raw_credential_leaks"])
                self.assertFalse(full["synthetic_marker_or_token_leak"])
                self.assertFalse(full["runtime_api_requested"])
                cases = {c["case"]:c for c in full["cases"]}
                for name in ("decoded-source-map", "deep-document", "iframe-password", "sitemap-only", "cross-module"):
                    self.assertTrue(cases[name]["reached"],name)
                self.assertEqual(cases["custom-password-dialog"]["outcome"],"TP")
                small = run_profile(lab,origin,destination,"small",size_limited=True)
                self.assertFalse(next(c for c in small["cases"] if c["case"]=="large-script")["reached"])
                small_report = json.loads((destination/"small.json").read_text())
                self.assertTrue(any("byte limit" in f["title"] for f in small_report["findings"]))
                explicit = run_profile(lab,origin,destination,"explicit",explicit=True)
                self.assertTrue(explicit["runtime_api_requested"])
                self.assertEqual(next(c for c in explicit["cases"] if c["case"]=="runtime-only-api")["outcome"],"TP")
        finally:
            for instance in (server,trap):
                instance.shutdown()
                instance.server_close()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    unittest.main()
