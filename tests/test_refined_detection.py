"""Harder source layouts, false-positive controls and AI-only review grounding."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gilbrt.cli import parser, run_audit
from gilbrt.js_parser import candidates
from gilbrt.scanner import scan
from tests import test_bundled_ai


class RefinedDetectionTests(unittest.TestCase):
    def reveal(self, text, html=False, checks=None):
        values = []
        findings = scan(text, "https://fixture.invalid/app.js", html=html, checks=checks or {"passwords"},
                        on_secret=lambda finding, value: values.append(value))
        return findings, values

    def test_password_values_and_nested_hydration_are_detected(self):
        cases = [
            ('const adminPasswordValue="refined-admin-91";', False, "refined-admin-91"),
            ('const credentials={passwordValue:"refined-object-82"};', False, "refined-object-82"),
            ('<script type="application/json">{"credentials":{"password":"refined-json-73"}}</script>', True, "refined-json-73"),
            (json.dumps({"records": [{"adminPasswordValue": "refined-nested-64"}]}), False, "refined-nested-64"),
        ]
        for text, html, expected in cases:
            with self.subTest(text=text):
                findings, values = self.reveal(text, html)
                self.assertIn(expected, values)
                self.assertEqual(values.count(expected), 1)
                self.assertNotIn(expected, str(findings))

    def test_help_text_and_non_password_properties_are_not_credentials(self):
        html_cases = [
            '<label>Password:</label><input type="password"><a>Forgot password?</a>',
            '<p>Password: must contain at least eight characters</p>',
            '<div>Password: invalid. Please try again.</div>',
            '<div>Password:</div><div>Reset your password here</div>',
        ]
        for text in html_cases:
            with self.subTest(text=text):
                self.assertEqual(self.reveal(text, True)[0], [])
        self.assertEqual(self.reveal('{"passwordHash":"not-plaintext", "password": false, "passwordValue":""}')[0], [])
        self.assertTrue(self.reveal('<p><b>Password:</b> actual-visible-53</p>', True)[0])

    def test_reconstructed_provider_tokens_and_specific_patterns(self):
        value = "sk-proj-Abc123Def456Ghi789Jkl012"
        for text in [f'const apiKey="sk-proj-"+"Abc123Def456Ghi789Jkl012";',
                     'const apiKey=atob("c2stcHJvai1BYmMxMjNEZWY0NTZHaGk3ODlKa2wwMTI=");']:
            findings, values = self.reveal(text, checks={"api-keys"})
            self.assertEqual(values, [value])
            self.assertNotIn(value, str(findings))
        findings, _ = self.reveal('const key="sk-ant-Abc123Def456Ghi789Jkl012";', checks={"api-keys"})
        self.assertEqual([f.title for f in findings], ["Potential Anthropic API secret"])

    def test_switch_gates_do_not_promote_theme_cases(self):
        findings, values = self.reveal('switch(accessCode){case "refined-switch-42":unlock();break;}', checks={"access-codes"})
        self.assertEqual(values, ["refined-switch-42"])
        self.assertTrue(findings)
        self.assertEqual(self.reveal('switch(theme){case "midnight":render();break;}', checks={"access-codes"})[0], [])

    def test_ai_can_review_validators_outside_static_pool(self):
        source = 'function verifyInvitation(value){return value === "refined-invite-37";}'
        self.assertEqual(candidates(source, include_password_assignments=True), [])
        reviewed = candidates(source, include_password_assignments=True, review=True)
        self.assertEqual([c.value for c, _, _ in reviewed], ["refined-invite-37"])
        analyzer = test_bundled_ai.BundledTests().stub_analyzer()
        findings = analyzer.analyze(source, "https://fixture.invalid/app.js")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "Info")
        self.assertNotIn("refined-invite-37", str(findings))
        arrow = 'const validateInvitation = v => v === "refined-arrow-19";'
        self.assertEqual(candidates(arrow), [])
        self.assertEqual([c.value for c, _, _ in candidates(arrow, review=True)], ["refined-arrow-19"])

    def test_ai_rejects_ordinary_predicate_and_model_inventions(self):
        for source in ['function chooseTheme(v){return v === "midnight";}',
                       'function isRoute(v){return v === "/home";}',
                       'if(v==="sidebar"){/* return false; authenticate(); */ render();}',
                       'const docs="function login(v){return v===\'fake\';}";']:
            self.assertEqual(candidates(source, review=True), [])
        analyzer = test_bundled_ai.BundledTests().stub_analyzer()
        analyzer.request.side_effect = None
        analyzer.request.return_value = {"done": True, "response": '{"candidate_ids":[999]}'}
        findings = analyzer.analyze('function authenticate(v){return v==="refined-value-28"}', "https://fixture.invalid/app.js")
        self.assertTrue(analyzer.failed)
        self.assertTrue(all(f.category == "Coverage" for f in findings))

    def test_bounded_const_alias_flows_and_negative_controls(self):
        for source in ['const q=location.hash;result.innerHTML=q;',
                       'const {hash}=location;result.innerHTML=hash;',
                       'const q=new URLSearchParams(location.search).get("q");result.innerHTML=q;']:
            self.assertTrue(self.reveal(source, checks={"browser-code"})[0])
        for source in ['const q=DOMPurify.sanitize(location.hash);result.innerHTML=q;',
                       'let q=location.hash;q="safe";result.innerHTML=q;',
                       'const q=location.hash;function display(q){result.innerHTML=q;}']:
            self.assertEqual(self.reveal(source, checks={"browser-code"})[0], [])

    def test_crawl_budget_warns_about_unfetched_admin_module(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                routes = {
                    "/": ("text/html", '<script type="module" src="/entry.js"></script>'),
                    "/entry.js": ("application/javascript", 'import("./admin.js");'),
                    "/admin.js": ("application/javascript", 'const adminPasswordValue="module-admin-19";'),
                }
                if self.path not in routes:
                    self.send_response(404)
                    self.end_headers()
                    return
                kind, body = routes[self.path]
                self.send_response(200)
                self.send_header("Content-Type", kind)
                self.end_headers()
                self.wfile.write(body.encode())

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            args = parser().parse_args(["--url", url, "--confirm-authorized", "--max-pages", "2", "--rate-limit", "0"])
            findings, metadata, _ = run_audit(args, {"passwords"})
            self.assertTrue(any(f.title == "Resource budget reached" for f in findings))
            self.assertEqual(metadata["credential_search"]["password_candidates"], 0)
            self.assertEqual(metadata["credential_search"]["javascript_resources_scanned"], 1)
            args.max_pages = 4
            findings, metadata, _ = run_audit(args, {"passwords"})
            self.assertTrue(any(f.category == "Password" for f in findings))
            self.assertFalse(any(f.title == "Resource budget reached" for f in findings))
            self.assertEqual(metadata["credential_search"]["javascript_resources_scanned"], 2)
            self.assertFalse(metadata["credential_search"]["credentials_validated"])
            self.assertNotIn("module-admin-19", str(findings))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
