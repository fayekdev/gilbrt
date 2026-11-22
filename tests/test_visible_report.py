"""Ensure local reveal tables and redacted exports remain separate."""

import io
import json
import tempfile
import unittest
from pathlib import Path

from rich.console import Console

from gilbrt.reporter import export, print_summary
from gilbrt.scanner import scan
from gilbrt.models import Finding


class VisibleReportTests(unittest.TestCase):
    """Cover multiple short secrets on one line and source-map wrapper identities."""

    def test_visible_password_rows_are_critical_and_unmasked(self) -> None:
        visible = {}
        findings = scan('const password="alpha7"; const db_password="bravo8";', "https://test.invalid/main.js",
                        checks={"passwords"}, on_secret=lambda finding, value: visible.__setitem__(id(finding), value))
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == "Critical" for f in findings))
        output = io.StringIO()
        print_summary(findings, Console(file=output, width=240), visible)
        rendered = output.getvalue()
        self.assertIn("alpha7", rendered)
        self.assertIn("bravo8", rendered)
        self.assertNotIn("REDACTED", rendered)
        self.assertEqual(rendered.count("alpha7"), 1)
        self.assertEqual(rendered.count("bravo8"), 1)
        self.assertNotIn("alpha7", str(findings))
        with tempfile.TemporaryDirectory() as directory:
            for fmt in ("json", "csv", "html", "ai"):
                file = Path(directory) / fmt
                export(findings, str(file), fmt, {})
                report = file.read_text(encoding="utf-8-sig")
                self.assertNotIn("alpha7", report)
                self.assertNotIn("bravo8", report)

    def test_default_table_remains_redacted(self) -> None:
        findings = scan('password="alpha7";', "https://test.invalid/main.js", checks={"passwords"})
        output = io.StringIO()
        print_summary(findings, Console(file=output, width=240))
        self.assertIn("REDACTED", output.getvalue())
        self.assertNotIn("alpha7", output.getvalue())

    def test_source_map_reveal_uses_wrapped_finding_identity(self) -> None:
        visible = {}
        text = json.dumps({"sourcesContent": ['if(password === "map-code")allow();']})
        findings = scan(text, "https://test.invalid/app.map", checks={"passwords"},
                        on_secret=lambda finding, value: visible.__setitem__(id(finding), value))
        mapped = [f for f in findings if "Source-map source" in f.evidence]
        self.assertTrue(mapped)
        self.assertTrue(any(visible.get(id(f)) == "map-code" for f in mapped))
        output = io.StringIO()
        print_summary(mapped, Console(file=output, width=240), visible)
        self.assertIn("map-code", output.getvalue())
        self.assertNotIn("REDACTED", output.getvalue())

    def test_control_characters_are_shown_as_escapes_in_visible_values(self) -> None:
        finding = Finding("Critical", "Password", "Password candidate", "https://test.invalid/", "Value: [REDACTED]", "Rotate")
        output = io.StringIO()
        print_summary([finding], Console(file=output, width=240), {id(finding): "abc\x1b[31mdef"})
        self.assertIn(r"abc\x1b[31mdef", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())


if __name__ == "__main__":
    unittest.main()
