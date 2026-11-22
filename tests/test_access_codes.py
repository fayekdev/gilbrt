"""Regression checks for exposed literals in client-side access gates."""

import json
import tempfile
import unittest
from pathlib import Path

from gilbrt.reporter import export
from gilbrt.scanner import scan


class AccessCodeTests(unittest.TestCase):
    """Cover comparison syntax, selection, redaction and lexical false positives."""

    def candidates(self, source: str, checks: set[str] | None = None):
        """Collect local-only reveal callbacks separately from redacted findings."""
        values = []
        findings = scan(source, "https://staging.invalid/gate.js", checks=checks or {"access-codes"},
                        on_secret=lambda finding, value: values.append(value))
        return findings, values

    def test_named_comparisons_and_reversed_literals(self) -> None:
        cases = [
            ('if (code === "4827") { allow(); }', "4827"),
            ("if ('gate-synthetic' == enteredCode) allow();", "gate-synthetic"),
            ("if (pin !== 7392) deny();", "7392"),
            ('return access_code != "gate-private";', "gate-private"),
            ('if (input.value.trim() === "gate-trimmed") allow();', "gate-trimmed"),
            ('if (document.getElementById("pin").value === "6093") allow();', "6093"),
            ('if ((accessCode) === ("grouped-code")) allow();', "grouped-code"),
        ]
        for source, value in cases:
            with self.subTest(source=source):
                findings, revealed = self.candidates(source)
                self.assertIn(value, revealed)
                self.assertNotIn(value, str(findings))

    def test_code_assignments_and_json_properties(self) -> None:
        for source, expected in [('const ACCESS_CODE="staging-gate";', "staging-gate"),
                                 ('const pin = 6543;', "6543"),
                                 ('{"accessCode": "json-gate"}', "json-gate")]:
            with self.subTest(source=source):
                self.assertIn(expected, self.candidates(source)[1])

    def test_password_comparisons_work_in_password_category(self) -> None:
        findings, revealed = self.candidates('if (password === "test-password") allow();', {"passwords"})
        self.assertEqual(revealed, ["test-password"])
        self.assertEqual(findings[0].title, "Hardcoded password comparison")

    def test_minified_if_is_labeled_as_review_candidate(self) -> None:
        findings, revealed = self.candidates('if(x==="gate-synthetic")a();')
        self.assertEqual(revealed, ["gate-synthetic"])
        self.assertEqual(findings[0].severity, "Info")
        self.assertIn("review", findings[0].title)

    def test_commented_example_and_dynamic_value_are_not_matches(self) -> None:
        source = '''// if(code === "comment-only") allow();
        /* if(pin === 1234) allow(); */
        const example = "if(code === 'quoted-example') allow();";
        if (code === serverCode) allow();
        if (count === 1) next();
        if (accessCode.length === 4) next();
        if (code === `dynamic-${runtime}`) allow();'''
        findings, revealed = self.candidates(source)
        self.assertFalse(findings)
        self.assertFalse(revealed)

    def test_escaped_literal_and_source_map(self) -> None:
        source = r'if (code === "\x34\u0038\x32\x37") allow();'
        self.assertIn("4827", self.candidates(source)[1])
        findings, revealed = self.candidates(json.dumps({"sourcesContent": ['if(code==="map-gate")allow();']}))
        self.assertIn("map-gate", revealed)
        self.assertTrue(any("Source-map source 0" in f.evidence for f in findings))

    def test_regex_quotes_do_not_hide_minified_access_gate(self) -> None:
        source = '''const escape = /["'`]/g; const login = e => e == "fixture-password" ? allow() : deny();'''
        findings, revealed = self.candidates(source)
        self.assertIn("fixture-password", revealed)
        self.assertTrue(findings)

    def test_template_interpolation_is_parsed_as_code(self) -> None:
        source = '''const view = `<p>${entered == "fixture-pin" ? "allowed" : "denied"}</p>`;'''
        self.assertIn("fixture-pin", self.candidates(source)[1])

    def test_exports_redact_codes_and_unselected_category_stays_quiet(self) -> None:
        source = 'if(code === "gate-private") allow();'
        self.assertFalse(scan(source, "https://staging.invalid/", checks={"api-keys"}))
        findings, _ = self.candidates(source)
        for fmt in ("json", "csv", "html", "ai"):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                filename = Path(directory) / "report"
                export(findings, str(filename), fmt, {})
                report = filename.read_text(encoding="utf-8-sig")
                self.assertNotIn("gate-private", report)
                self.assertIn("Hardcoded access code comparison", report)


if __name__ == "__main__":
    unittest.main()
