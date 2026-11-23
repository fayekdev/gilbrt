"""Real loopback GUI integration: engine, scope, session isolation and exports."""

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import requests

from gilbrt.cli import AuditCancelled
from gilbrt.gui import APIError, DEFAULT_SETTINGS, GUIState, GUIServer, discover_models, validate_settings

FIXTURE_PASSWORD = "synthetic-local-fixture-password-908172"


class Fixture(BaseHTTPRequestHandler):
    visits = []

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.visits.append(self.path)
        if self.path == "/robots.txt":
            body, kind = "User-agent: *\nDisallow: /private\n", "text/plain"
        elif self.path == "/app.js":
            body, kind = f'const dbPassword = "{FIXTURE_PASSWORD}";', "application/javascript"
        elif self.path == "/api/tags":
            body, kind = json.dumps({"models": [
                {"name": "fixture:local", "size": 4096},
                {"name": "fixture:cloud", "size": 4096},
                {"name": "remote-alias", "size": 4096, "remote_host": "remote.example"},
            ]}), "application/json"
        else:
            body, kind = '<script src="/app.js"></script><a href="/private">private</a>', "text/html"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.end_headers()
        self.wfile.write(body.encode())


class GUITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.fixture_thread = threading.Thread(target=cls.fixture.serve_forever, daemon=True)
        cls.fixture_thread.start()
        cls.target = f"http://127.0.0.1:{cls.fixture.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.fixture.shutdown()
        cls.fixture.server_close()
        cls.fixture_thread.join(2)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.settings_path = Path(self.directory.name) / "settings.json"
        self.state = GUIState(self.settings_path)
        self.server = GUIServer(0, self.state)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.session = requests.Session()
        self.session.trust_env = False
        self.base = self.server.origin
        self.session.headers["X-Gilbrt-Token"] = self.state.token
        Fixture.visits.clear()

    def tearDown(self):
        self.state.cancel_audit()
        if self.state.thread:
            self.state.thread.join(3)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.session.close()
        self.directory.cleanup()

    def start(self, **overrides):
        settings = {**DEFAULT_SETTINGS, "rate_limit": 0, "checks": ["passwords"], **overrides}
        return self.session.post(self.base + "/api/audit", json={
            "target": self.target, "authorized": True, "settings": settings}, timeout=3)

    def finish(self):
        self.state.thread.join(5)
        self.assertFalse(self.state.thread.is_alive())
        return self.session.get(self.base + "/api/state", timeout=3).json()

    def test_real_audit_redaction_scope_and_all_exports(self):
        self.assertEqual(self.start().status_code, 202)
        data = self.finish()
        self.assertEqual(data["job"]["status"], "complete")
        self.assertEqual(data["report"]["metadata"]["resources_scanned"], 2)
        self.assertEqual(data["report"]["metadata"]["resources_attempted"], 2)
        self.assertTrue(any(f["category"] == "Password" for f in data["report"]["findings"]))
        self.assertNotIn("/private", Fixture.visits)
        self.assertNotIn(FIXTURE_PASSWORD, json.dumps(data))
        self.assertTrue(any(event["stage"] == "Resource analyzed" for event in data["job"]["events"]))
        for fmt in ("json", "html", "csv", "ai"):
            response = self.session.get(self.base + "/api/export", params={"format": fmt}, timeout=3)
            self.assertEqual(response.status_code, 200)
            self.assertIn("attachment", response.headers["Content-Disposition"])
            self.assertNotIn(FIXTURE_PASSWORD, response.text)
            self.assertIn("Potential exposed password", response.text)
        self.assertEqual(self.session.get(self.base+"/api/export?format=exe").status_code, 400)

    def test_authorization_required_before_requests(self):
        response = self.session.post(self.base+"/api/audit", json={"target": self.target, "authorized": False})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Fixture.visits, [])
        self.assertIsNone(self.state.job)

    def test_token_origin_host_and_asset_allowlist(self):
        for endpoint in ("/api/state", "/api/models", "/api/export"):
            response = self.session.get(self.base+endpoint, headers={"X-Gilbrt-Token": "wrong"})
            self.assertEqual(response.status_code, 403)
        for headers in ({"Origin": "https://other.example"}, {"Host": "attacker.example"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.session.get(self.base+"/api/bootstrap", headers=headers).status_code, 403)
        self.assertEqual(self.session.post(self.base+"/api/settings", json={}, headers={"X-Gilbrt-Token":"wrong"}).status_code, 403)
        self.assertEqual(self.session.get(self.base+"/gui.py").status_code, 404)
        self.assertEqual(self.session.get(self.base+"/").status_code, 200)

    def test_settings_persist_without_targets_or_reports(self):
        settings = {**DEFAULT_SETTINGS, "max_pages": 8, "ai_max_chunks": 3, "checks": ["headers"], "model":"bundled"}
        response = self.session.post(self.base+"/api/settings", json=settings)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(GUIState(self.settings_path).settings, settings)
        self.assertNotIn("target", self.settings_path.read_text())
        self.assertNotIn("findings", self.settings_path.read_text())

    def test_bad_limits_and_remote_model_urls_rejected(self):
        for changes in ({"rate_limit": float("inf")}, {"max_pages": True}, {"checks": []},
                        {"max_resource_mb": 65}, {"ai_candidate_limit": 23}, {"ai_max_chunks": -1},
                        {"ollama_url":"http://remote.example:11434"}, {"model":"fixture:cloud"}):
            with self.assertRaises(APIError):
                validate_settings(changes)
        self.assertEqual(self.session.post(self.base+"/api/settings", json={"unknown":True}).status_code, 400)

    def test_models_only_list_local_installed_choices(self):
        with patch("gilbrt.gui.bundled_available", return_value=True):
            data = discover_models(self.target)
        ids = [model["id"] for model in data["choices"]]
        self.assertIn("", ids)
        self.assertIn("bundled", ids)
        self.assertIn("fixture:local", ids)
        self.assertNotIn("fixture:cloud", ids)
        self.assertNotIn("remote-alias", ids)

    def test_selected_model_and_ai_settings_reach_shared_engine(self):
        captured = []
        def run(args, selected, progress, cancelled):
            captured.append((args.local_model, args.ai_max_chunks, args.ai_candidate_limit, args.ollama_url, selected))
            return [], {"resources_scanned":0}, {}
        with patch("gilbrt.gui.discover_models", return_value={"choices":[{"id":"fixture:local"}]}), patch("gilbrt.gui.run_audit", side_effect=run):
            self.assertEqual(self.start(model="fixture:local", ai_max_chunks=2, ai_candidate_limit=50).status_code, 202)
            data = self.finish()
        self.assertEqual(data["job"]["status"], "complete")
        self.assertEqual(captured[0][:3], ("fixture:local", 2, 50))
        self.assertIn("local-ai", captured[0][4])

    def test_cancel_preserves_previous_report_and_blocks_overlap(self):
        previous = {"findings":[],"metadata":{},"session":{}}
        self.state.report = previous
        def waiting(args, selected, progress, cancelled):
            while not cancelled():
                time.sleep(.01)
            raise AuditCancelled()
        with patch("gilbrt.gui.run_audit", side_effect=waiting):
            self.assertEqual(self.start().status_code, 202)
            self.assertEqual(self.start().status_code, 409)
            self.assertEqual(self.session.post(self.base+"/api/cancel", json={}).status_code, 200)
            data = self.finish()
        self.assertEqual(data["job"]["status"], "cancelled")
        self.assertEqual(data["report"], previous)

    def test_cancellation_interrupts_long_request_pacing(self):
        self.assertEqual(self.start(rate_limit=30).status_code, 202)
        deadline = time.monotonic()+2
        while not Fixture.visits and time.monotonic()<deadline:
            time.sleep(.01)
        self.session.post(self.base+"/api/cancel", json={})
        data = self.finish()
        self.assertEqual(data["job"]["status"], "cancelled")
        self.assertIsNone(data["report"])

    def test_unavailable_model_and_cross_origin_seed_do_not_scan(self):
        with patch("gilbrt.gui.discover_models", return_value={"choices":[{"id":""}]}):
            self.assertEqual(self.start(model="missing:local").status_code, 400)
        response = self.session.post(self.base+"/api/audit", json={"authorized":True,"target":self.target,"include_urls":["https://elsewhere.example/config"]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(Fixture.visits, [])


if __name__ == "__main__":
    unittest.main()
