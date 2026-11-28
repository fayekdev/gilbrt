"""CLI-to-GUI report handoff, redaction, atomicity and headless launch."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import requests

from gilbrt.cli import main
from gilbrt.gui import GUIState, GUIServer
from gilbrt.models import Finding
from gilbrt.report_store import REPORT_NAME, read_report, save_report

SECRET = "saved-test-8192"


class ReportStoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / REPORT_NAME
        self.finding = Finding("Critical", "Password", "Potential exposed password", "http://127.0.0.1/[resource-test]",
                               "Line 1; [REDACTED]; literal candidate", "Review and rotate if real")
        self.metadata = {"target":"http://127.0.0.1/[resource-test]", "resources_scanned":1, "search_categories":["passwords"]}

    def test_roundtrip_restores_findings_but_never_revealed_values(self):
        save_report(self.path, [self.finding], self.metadata)
        state = GUIState(self.root/"settings.json")
        self.assertEqual(state.report["findings"][0]["title"], self.finding.title)
        self.assertEqual(state.job["source"], "cli")
        self.assertEqual(state.report["session"]["target_origin"], "http://127.0.0.1")
        self.assertEqual(state.evidence(state.report_id,0)["evidence"], self.finding.evidence)
        self.assertEqual(state.revealed_evidence,{})
        self.assertNotIn("report",state.snapshot(state.report_id))

    def test_existing_export_recomputes_assessment_and_ignores_session_secrets(self):
        save_report(self.path,[self.finding],{**self.metadata,"resources_scanned":0})
        document=json.loads(self.path.read_text())
        document.update(assessment={"status":"bounded"},session={"target_origin":"injected"},revealed_evidence={"0":SECRET})
        self.path.write_text(json.dumps(document),encoding="utf-8")
        state=GUIState(self.root/"settings.json",report_path=self.path)
        self.assertEqual(state.job["status"],"failed")
        self.assertEqual(state.report["assessment"]["status"],"source_scan_failed")
        self.assertNotIn(SECRET,json.dumps(state.snapshot()))

    def test_reload_picks_up_cli_result_but_does_not_interrupt_running_job(self):
        state=GUIState(self.root/"settings.json")
        self.assertIsNone(state.report)
        save_report(self.path,[self.finding],self.metadata)
        state.snapshot()
        old_id=state.report_id
        state.job.update(status="running")
        save_report(self.path,[],self.metadata)
        state.snapshot()
        self.assertEqual(state.report_id,old_id)
        state.job.update(status="complete")
        state.snapshot()
        self.assertNotEqual(state.report_id,old_id)
        self.assertEqual(state.report["findings"],[])

    def test_old_saved_report_does_not_replace_newer_in_memory_audit(self):
        state=GUIState(self.root/"settings.json")
        save_report(self.path,[self.finding],self.metadata)
        state._last_finished_ns=self.path.stat().st_mtime_ns+1
        state.report={"findings":[],"metadata":{},"session":{}}
        state.report_id="newer-audit"
        state.job={"status":"complete"}
        state.snapshot()
        self.assertEqual(state.report_id,"newer-audit")

    def test_bad_report_fails_safely_and_preserves_prior_report(self):
        save_report(self.path,[self.finding],self.metadata)
        state=GUIState(self.root/"settings.json")
        old_id=state.report_id
        self.path.write_text("invalid-private-source-text",encoding="utf-8")
        state.snapshot()
        self.assertEqual(state.report_id,old_id)
        self.assertIsNotNone(state.saved_report_error)
        with self.assertRaises(ValueError) as error:
            read_report(self.path)
        self.assertNotIn("invalid-private-source-text",str(error.exception))
        with self.assertRaises(ValueError):
            GUIState(self.root/"settings.json",report_path=self.path)

    def test_atomic_failure_keeps_previous_report_and_removes_tempfile(self):
        save_report(self.path,[self.finding],self.metadata)
        previous=self.path.read_bytes()
        with patch("gilbrt.report_store.os.replace",side_effect=OSError("test")):
            with self.assertRaises(OSError):
                save_report(self.path,[],self.metadata)
        self.assertEqual(self.path.read_bytes(),previous)
        self.assertEqual(list(self.root.glob(".cli-report-*.tmp")),[])

    def test_import_limits_and_schema_are_enforced(self):
        save_report(self.path,[self.finding],self.metadata)
        with patch("gilbrt.report_store.MAX_REPORT_BYTES",16):
            with self.assertRaises(ValueError):
                read_report(self.path)
        document=json.loads(self.path.read_text())
        for bad in [[],{**document,"tool":"unrelated"},{**document,"findings":[{"severity":"Critical"}]},
                    {**document,"metadata":{**self.metadata,"resources_scanned":True}},
                    {**document,"metadata":{**self.metadata,"resource_inventory":"invalid"}},
                    {**document,"metadata":{**self.metadata,"local_ai":"invalid"}}]:
            self.path.write_text(json.dumps(bad),encoding="utf-8")
            with self.assertRaises(ValueError):
                read_report(self.path)

    def test_existing_report_command_and_no_browser_reach_gui_without_audit(self):
        with patch("gilbrt.gui.serve",return_value=0) as serve,patch("gilbrt.cli.run_audit") as run:
            self.assertEqual(main(["--gui-report",str(self.path),"--no-browser"]),0)
            serve.assert_called_once_with(4174,open_browser=False,report_path=str(self.path))
            run.assert_not_called()

    def test_headless_server_does_not_attempt_browser_launch(self):
        state=GUIState(self.root/"settings.json")
        server=MagicMock()
        server.state=state
        server.origin="http://127.0.0.1:4174"
        server.forwarded_origin=None
        server.serve_forever.side_effect=KeyboardInterrupt
        with patch("gilbrt.gui.GUIState",return_value=state),patch("gilbrt.gui.GUIServer",return_value=server),patch("gilbrt.gui.webbrowser.open") as browser:
            self.assertEqual(main(["--gui","--no-browser"]),0)
            browser.assert_not_called()
            server.server_close.assert_called_once()

    def test_cli_subprocess_exits_then_gui_bootstraps_saved_result_without_rescanning(self):
        visits=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):
                pass
            def do_GET(self):
                visits.append(self.path)
                self.send_response(404 if self.path=="/robots.txt" else 200)
                self.send_header("Content-Type","text/html")
                self.end_headers()
                if self.path!="/robots.txt":
                    self.wfile.write(('<script>const password="'+SECRET+'";</script>').encode())
        target=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        target_thread=threading.Thread(target=target.serve_forever,daemon=True)
        target_thread.start()
        gui=None
        session=requests.Session()
        session.trust_env=False
        try:
            command=[sys.executable,"-m","gilbrt","--url",f"http://127.0.0.1:{target.server_port}/",
                     "--confirm-authorized","--search","passwords","--rate-limit","0","--save-gui","--show-secrets"]
            completed=subprocess.run(command,env={**os.environ,"GILBRT_RUNTIME":str(self.root)},capture_output=True,timeout=20)
            self.assertEqual(completed.returncode,0,completed.stderr.decode(errors="replace"))
            self.assertIn(SECRET.encode(),completed.stdout)
            self.assertNotIn(SECRET,self.path.read_text())
            before=len(visits)
            state=GUIState(self.root/"settings.json")
            gui=GUIServer(0,state)
            gui_thread=threading.Thread(target=gui.serve_forever,daemon=True)
            gui_thread.start()
            bootstrap=session.get(gui.origin+"/api/bootstrap",timeout=3).json()
            self.assertEqual(bootstrap["job"]["status"],"complete")
            self.assertTrue(any(f["category"]=="Password" for f in bootstrap["report"]["findings"]))
            self.assertEqual(len(visits),before)
            self.assertNotIn(SECRET,json.dumps(bootstrap))
            exported=session.get(gui.origin+"/api/export?format=json",headers={"X-Gilbrt-Token":bootstrap["token"]},timeout=3)
            self.assertEqual(exported.status_code,200)
            self.assertNotIn(SECRET,exported.text)
            self.assertEqual(session.get(gui.origin+"/api/state",timeout=3).status_code,403)
            without_save=self.root/"without-save"
            plain=subprocess.run([part for part in command if part!="--save-gui"],
                                 env={**os.environ,"GILBRT_RUNTIME":str(without_save)},capture_output=True,timeout=20)
            self.assertEqual(plain.returncode,0)
            self.assertFalse((without_save/REPORT_NAME).exists())
        finally:
            if gui is not None:
                gui.shutdown();gui.server_close();gui_thread.join()
            session.close()
            target.shutdown();target.server_close();target_thread.join()


if __name__=="__main__":
    unittest.main()
