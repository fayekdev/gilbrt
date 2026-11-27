"""Offline source checks must never resolve hosts, crawl references or fetch models."""

import unittest
from unittest.mock import patch

from gilbrt.cli import AuditCancelled, parser
from gilbrt.offline import run_local_audit, validate_files


class OfflineTests(unittest.TestCase):
    def args(self):
        args = parser().parse_args([])
        args.show_secrets = False
        return args

    def test_source_detection_without_network_or_dns(self):
        files = [{"name":"app.js", "content":'const dbPassword="offline-synthetic-82916"; fetch("https://must-not-fetch.invalid/data");'},
                 {"name":"index.html", "content":'<script src="https://must-not-fetch.invalid/app.js"></script>'}]
        with patch("requests.sessions.Session.request", side_effect=AssertionError("Network request")), \
             patch("socket.getaddrinfo", side_effect=AssertionError("DNS lookup")):
            found, metadata, visible = run_local_audit(self.args(), {"passwords","endpoints","headers","tls","breaches"},files)
        self.assertTrue(any(finding.category == "Password" for finding in found))
        self.assertEqual(metadata["mode"], "files")
        self.assertEqual(metadata["resources_scanned"], 2)
        self.assertEqual(metadata["unavailable_checks"], ["breaches","headers","tls"])
        self.assertFalse(metadata["hibp_queried"])
        self.assertFalse(visible)
        self.assertNotIn("offline-synthetic-82916", repr(found))
        self.assertNotIn("app.js", repr(metadata))

    def test_limits_and_cancellation(self):
        files = [{"name":"first.js","content":"let x=1"},{"name":"second.js","content":"let x=2"}]
        args = self.args()
        args.max_pages = 1
        found, meta, _ = run_local_audit(args,{"passwords"},files)
        self.assertEqual(meta["resources_scanned"],1)
        self.assertTrue(any(finding.category == "Coverage" for finding in found))
        with self.assertRaises(AuditCancelled):
            run_local_audit(args,{"passwords"},files,cancelled=lambda:True)

    def test_file_validation(self):
        for files in ([], [{"name":"file.exe","content":"text"}], [{"name":"file.js","content":"\x00binary"}],
                      [{"name":"file.js","content":None}], [{"name":"file.js","content":"x","extra":"field"}]):
            with self.subTest(files=files), self.assertRaises(ValueError):
                validate_files(files)
        with patch("gilbrt.offline.MAX_UPLOAD_BYTES",2), self.assertRaises(ValueError):
            validate_files([{"name":"file.js","content":"long"}])

    def test_selected_local_model_uses_same_loopback_backend_and_closes(self):
        args = self.args()
        args.local_model = "installed:local"
        args.ai_max_chunks = 2
        with patch("gilbrt.offline.LocalAnalyzer") as constructor:
            model = constructor.return_value
            model.analyze.return_value = []
            model.skipped = False
            model.candidate_limit_reached = False
            model.completed = 1
            model.failed = False
            _, meta, _ = run_local_audit(args,{"passwords","local-ai"},[{"name":"source.js","content":"const x=1"}])
            constructor.assert_called_once_with("installed:local","http://127.0.0.1:11434",2)
            model.close.assert_called_once()
            self.assertTrue(meta["local_ai"]["enabled"])


if __name__ == "__main__":
    unittest.main()
