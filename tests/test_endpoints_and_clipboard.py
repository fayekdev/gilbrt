"""Coverage for passive endpoint inventory, added providers and report copying."""

import json
import unittest
from unittest.mock import patch

from gilbrt.models import Finding
from gilbrt.reporter import copy_to_clipboard, render_report
from gilbrt.scanner import scan
from gilbrt.updater import update_installation


class EndpointAndClipboardTests(unittest.TestCase):
    def test_endpoint_inventory_does_not_expose_literal(self) -> None:
        source = "fetch('/api/private/users?token=do-not-print'); const supabaseUrl='https://abcdefgh.supabase.co'"
        findings = scan(source, "https://example.test/app.js", checks={"endpoints"})
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(item.category == "Endpoint" for item in findings))
        self.assertNotIn("private/users", " ".join(item.evidence + item.url for item in findings))
        self.assertTrue(all(item.severity == "Info" for item in findings))

    def test_supabase_and_provider_tokens_are_redacted(self) -> None:
        values = ["sb_secret_" + "A" * 30, "npm_" + "B" * 36, "glpat-" + "C" * 24]
        findings = scan(" ".join(values), "https://example.test/app.js", checks={"api-keys", "tokens"})
        report = render_report(findings, "json", {})
        self.assertGreaterEqual(len(findings), 3)
        self.assertTrue(all(value not in report for value in values))
        json.loads(report)

    def test_supabase_service_role_is_critical(self) -> None:
        token = "eyJ" + "A" * 24 + "." + "B" * 24 + "." + "C" * 24
        findings = scan(f"const SUPABASE_SERVICE_ROLE_KEY='{token}'", "https://example.test/app.js",
                        checks={"api-keys", "tokens"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Critical")
        self.assertNotIn(token, render_report(findings, "json", {}))

    @patch("gilbrt.reporter.shutil.which", return_value="/usr/bin/wl-copy")
    @patch("gilbrt.reporter.subprocess.run")
    def test_clipboard_receives_rendered_redacted_report(self, run, _which) -> None:
        run.return_value.returncode = 0
        text = render_report([Finding("Info", "Test", "Title", "resource", "safe", "review")], "json", {})
        copy_to_clipboard(text)
        self.assertEqual(run.call_args.kwargs["input"], text)

    @patch("gilbrt.updater.Path.is_dir", return_value=True)
    @patch("gilbrt.updater.Path.is_file", return_value=True)
    @patch("gilbrt.updater._run")
    def test_updater_requires_clean_checkout_and_fast_forward(self, run, _file, _dir) -> None:
        run.side_effect = ["", "a" * 40, "", "", "b" * 40]
        self.assertEqual(update_installation(), "gilbrt updated to bbbbbbb.")
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["git", "pull", "--ff-only"], commands)


if __name__ == "__main__":
    unittest.main()
