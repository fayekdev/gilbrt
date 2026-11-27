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
from gilbrt.gui import APIError, DEFAULT_SETTINGS, GUIState, GUIServer, codespaces_origin, discover_models, validate_settings

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
        index = next(i for i, f in enumerate(data["report"]["findings"]) if f["category"] == "Password")
        evidence_url = self.base + "/api/evidence"
        params = {"index": index, "report_id": data["report_id"]}
        revealed = self.session.get(evidence_url, params=params)
        self.assertEqual(revealed.status_code, 200)
        self.assertIn(FIXTURE_PASSWORD, revealed.json()["evidence"])
        self.assertEqual(revealed.headers["Cache-Control"], "no-store")
        self.assertEqual(self.session.get(evidence_url, params=params, headers={"X-Gilbrt-Token": "wrong"}).status_code, 403)
        self.assertEqual(self.session.get(evidence_url, params={**params, "report_id": "stale"}).status_code, 409)
        self.assertEqual(self.session.get(evidence_url, params={**params, "index": -1}).status_code, 404)
        unchanged = self.session.get(self.base + "/api/state", params={"report_id": data["report_id"]}).json()
        self.assertNotIn("report", unchanged)
        self.assertEqual(unchanged["job"]["status"], "complete")
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

    def test_offline_file_audit_export_and_authorization(self):
        payload = {"authorized":True,"settings":{**DEFAULT_SETTINGS,"model":"","checks":["passwords","headers","tls"]},
                   "files":[{"name":"fixture.js","content":f'const dbPassword="{FIXTURE_PASSWORD}";'}]}
        with patch("gilbrt.gui.ScopedClient") as network:
            response = self.session.post(self.base+"/api/offline",json=payload)
            self.assertEqual(response.status_code,202)
            data = self.finish()
            network.assert_not_called()
        self.assertEqual(data["job"]["status"],"complete")
        self.assertEqual(data["report"]["metadata"]["mode"],"files")
        self.assertEqual(data["report"]["session"]["target_origin"],"Local files")
        self.assertTrue(any(f["category"] == "Password" for f in data["report"]["findings"]))
        self.assertNotIn(FIXTURE_PASSWORD,json.dumps(data))
        self.assertEqual(Fixture.visits,[])
        for fmt in ("json","html","csv","ai"):
            exported = self.session.get(self.base+"/api/export",params={"format":fmt})
            self.assertEqual(exported.status_code,200)
            self.assertNotIn(FIXTURE_PASSWORD,exported.text)
        self.assertEqual(self.session.post(self.base+"/api/offline",json={**payload,"authorized":False}).status_code,400)
        self.assertEqual(self.session.post(self.base+"/api/offline",json=payload,headers={"X-Gilbrt-Token":"wrong"}).status_code,403)
        self.assertEqual(self.session.post(self.base+"/api/offline",json={**payload,"files":[]}).status_code,400)

    def test_token_origin_host_and_asset_allowlist(self):
        for endpoint in ("/api/state", "/api/models", "/api/export"):
            response = self.session.get(self.base+endpoint, headers={"X-Gilbrt-Token": "wrong"})
            self.assertEqual(response.status_code, 403)
        for headers in ({"Origin": "https://other.example"}, {"Host": "attacker.example"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.session.get(self.base+"/api/bootstrap", headers=headers).status_code, 403)
        self.assertEqual(self.session.post(self.base+"/api/settings", json={}, headers={"X-Gilbrt-Token":"wrong"}).status_code, 403)
        self.assertEqual(self.session.get(self.base+"/gui.py").status_code, 404)
        self.assertEqual(self.session.get(self.base+"/").status_code, 200)

    def configure_codespaces(self):
        with patch.dict("os.environ", {"CODESPACES":"true", "CODESPACE_NAME":"my-test-space",
                                      "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN":"app.github.dev"}):
            origin = codespaces_origin(self.server.server_port)
        self.server.forwarded_origin = origin
        self.server.allowed_origins.add(origin)
        return origin

    def test_codespaces_bootstrap_settings_and_real_audit(self):
        origin = self.configure_codespaces()
        self.session.headers.update({"Host": origin.removeprefix("https://"), "Origin": origin,
                                     "Sec-Fetch-Site":"same-origin"})
        bootstrap = self.session.get(self.base+"/api/bootstrap")
        self.assertEqual(bootstrap.status_code, 200)
        self.assertEqual(bootstrap.json()["token"], self.state.token)
        self.assertEqual(self.session.post(self.base+"/api/settings", json={"max_pages":7}).status_code, 200)
        self.assertEqual(self.start().status_code, 202)
        self.assertEqual(self.finish()["job"]["status"], "complete")
        # A proxy may rewrite Host to loopback while preserving browser Origin.
        self.assertEqual(self.session.get(self.base+"/api/state", headers={"Host":self.base.removeprefix("http://")}).status_code, 200)
        self.assertEqual(self.session.get(self.base+"/api/state", headers={"Host":f"localhost:{self.server.server_port}"}).status_code, 200)

    def test_codespaces_rejects_other_spaces_origins_and_missing_token(self):
        origin = self.configure_codespaces()
        host = origin.removeprefix("https://")
        for bad_host in (host.replace("my-test-space", "another-space"),host+".attacker.example",
                         "attacker.example",host.replace(str(self.server.server_port),"1")):
            self.assertEqual(self.session.get(self.base+"/api/bootstrap", headers={"Host":bad_host}).status_code, 403)
        for bad_origin in ("https://another-space.app.github.dev", "null", "http://"+host,
                           "http://localhost:1", "http://127.0.0.1:1"):
            self.assertEqual(self.session.post(self.base+"/api/settings", headers={"Host":host,"Origin":bad_origin}, json={}).status_code, 403)
        self.assertEqual(self.session.get(self.base+"/api/state", headers={"Host":host,"Origin":origin,"X-Gilbrt-Token":"wrong"}).status_code, 403)
        self.assertEqual(self.session.get(self.base+"/api/bootstrap", headers={"Host":host,"Sec-Fetch-Site":"cross-site"}).status_code, 403)
        # Forged forwarding headers cannot add an origin to the allowlist.
        self.assertEqual(self.session.get(self.base+"/api/bootstrap", headers={"Host":"attacker.example","X-Forwarded-Host":host,"X-Forwarded-Proto":"https"}).status_code, 403)

    def test_codespaces_independent_host_and_origin_rewrites(self):
        origin = self.configure_codespaces()
        # Codespaces may independently preserve or rewrite each header. Exercise
        # bootstrap and POSTs, not just static assets, across every exact pairing.
        hosts = [origin.removeprefix("https://"), self.base.removeprefix("http://"),
                 f"localhost:{self.server.server_port}"]
        origins = [origin, self.base, f"http://localhost:{self.server.server_port}"]
        for host in hosts:
            for browser_origin in origins:
                with self.subTest(host=host, origin=browser_origin):
                    headers = {"Host":host, "Origin":browser_origin,"Sec-Fetch-Site":"same-origin"}
                    self.assertEqual(self.session.get(self.base+"/api/bootstrap",headers=headers).status_code, 200)
                    self.assertEqual(self.session.post(self.base+"/api/settings",headers=headers,json={"max_pages":9}).status_code, 200)
                    self.assertEqual(self.session.post(self.base+"/api/settings",headers={**headers,"X-Gilbrt-Token":"wrong"},json={}).status_code, 403)
                    self.assertEqual(self.session.post(self.base+"/api/settings",headers={**headers,"Sec-Fetch-Site":"cross-site"},json={}).status_code, 403)
        self.session.headers.update({"Host":hosts[0],"Origin":origins[2],"Sec-Fetch-Site":"same-origin"})
        self.assertEqual(self.start().status_code, 202)
        self.assertEqual(self.finish()["job"]["status"], "complete")

    def test_codespaces_document_navigation_from_editor(self):
        origin = self.configure_codespaces()
        headers = {"Host":origin.removeprefix("https://"),"Sec-Fetch-Site":"cross-site","Sec-Fetch-Mode":"navigate"}
        self.assertEqual(self.session.get(self.base+"/",headers=headers).status_code, 200)
        self.assertEqual(self.session.get(self.base+"/api/bootstrap",headers=headers).status_code, 403)

    def test_codespaces_environment_validation(self):
        environment = {"CODESPACES":"true", "CODESPACE_NAME":"my-test-space",
                       "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN":"app.github.dev"}
        with patch.dict("os.environ", environment):
            self.assertEqual(codespaces_origin(4174), "https://my-test-space-4174.app.github.dev")
            for changes in ({"CODESPACES":"false"}, {"CODESPACE_NAME":""},
                            {"CODESPACE_NAME":"bad/path"}, {"GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN":"app.github.dev/path"},
                            {"GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN":"app.github.dev:443"},
                            {"GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN":""}):
                with patch.dict("os.environ", changes):
                    self.assertIsNone(codespaces_origin(4174))

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
        self.assertEqual(data["job"]["status"], "failed")
        self.assertEqual(data["report"]["assessment"]["status"], "source_scan_failed")
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

    def test_snapshot_shares_immutable_report_but_isolates_job(self):
        self.state.report = {"findings": [], "metadata": {}}
        self.state.job = {"status": "complete", "events": []}
        snapshot = self.state.snapshot()
        self.assertIs(snapshot["report"], self.state.report)
        snapshot["job"]["events"].append({"stage": "unrelated"})
        self.assertEqual(self.state.job["events"], [])

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
