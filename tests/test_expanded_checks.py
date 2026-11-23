"""Regression coverage for bounded folding and passive web-security checks."""

import json
import tempfile
import unittest
from pathlib import Path

import requests

from gilbrt.cli import search_selection
from gilbrt.headers import analyze_headers
from gilbrt.reporter import export
from gilbrt.scanner import scan


class ExpandedCheckTests(unittest.TestCase):
    def scan(self, source, checks, html=False):
        values = []
        findings = scan(source, "https://demo.invalid/app", html=html, checks=set(checks),
                        on_secret=lambda finding, value: values.append(value))
        return findings, values

    def test_reconstructs_complete_constant_credentials(self):
        examples = [
            ('const password="fold-"+"complete-38";', "fold-complete-38"),
            ('const password=atob("Zm9sZC1kZWNvZGVkLTU5");', "fold-decoded-59"),
            ('const password=atob("Zm9sZC11bnBhZGRlZA");', "fold-unpadded"),
            ('const password=String.fromCharCode(102,111,108,100,45,55,50);', "fold-72"),
            ('const\tprefix="fold-"; const password=prefix+"bound-83";', "fold-bound-83"),
            ('const digits=[4,8,2,7]; if(pin===digits.join("")) unlock();', "4827"),
            ('if(pin===[8,4,2,6].join("")) unlock();', "8426"),
            ('const password="pin-"+73;', "pin-73"),
        ]
        for source, expected in examples:
            with self.subTest(source=source):
                findings, values = self.scan(source, {"passwords", "access-codes"})
                self.assertIn(expected, values)
                self.assertNotIn(expected, str(findings))

    def test_constant_folding_rejects_dynamic_mutable_and_oversized_expressions(self):
        examples = [
            'let part="prefix-"; const password=part+"mutable";',
            'const password=customDecode("Zm9v");',
            'const password=atob("not valid base64!");',
            'const password=atob(fetch("/secret"));',
            'function atob(x){return runtime;} const password=atob("Zm9v");',
            'function check(atob){const password=atob("Zm9v");}',
            'const String=custom;const password=String.fromCharCode(102,111,111);',
            'const password=String.fromCharCode(runtime);',
            'const password=1+2;',
            'const password="prefix-"+071;',
            'const password="prefix-"+9007199254740993;',
            'const password="prefix-"+runtime;',
            'const digits=[4,8,2,7]; digits.push(1); if(pin===digits.join("")) unlock();',
            'const digits=[4,8,2,7]; mutate(digits); if(pin===digits.join("")) unlock();',
            'const digits=[4,8,2,7]; const alias=digits; if(pin===digits.join("")) unlock();',
            'const digits=[4,8,2,7]; if(pin===digits.reverse().join("")) unlock();',
            'const part="outside";function check(part){const password=part+"-suffix";}',
            'const password=part+"-suffix";const part="later";',
            'const password=' + '+'.join('"aaaaaaaa"' for _ in range(150)) + ';',
        ]
        for source in examples:
            with self.subTest(source=source[:100]):
                self.assertEqual(self.scan(source, {"passwords", "access-codes"})[1], [])

    def test_connections_redact_every_export(self):
        value = "postgresql://demo:private-db-pass-83@db.invalid/app"
        findings, values = self.scan(f'const db="{value}";', {"connections"})
        self.assertEqual(values, [value])
        self.assertEqual(findings[0].category, "Connection")
        with tempfile.TemporaryDirectory() as directory:
            for fmt in ("json", "html", "csv", "ai"):
                path = Path(directory) / ("report." + fmt)
                export(findings, str(path), fmt, {})
                self.assertNotIn("private-db-pass-83", path.read_text(encoding="utf-8-sig"))

    def test_connection_placeholders_and_category_selection(self):
        for text in ('postgresql://user:YOUR_PASSWORD_HERE@db.invalid/app',
                     'postgresql://db.invalid/app', 'redis://user:${PASSWORD}@cache.invalid'):
            self.assertEqual(self.scan(text, {"connections"})[0], [])
        self.assertEqual(self.scan('mysql://user:real-demo-password@db.invalid/app', {"passwords"})[0], [])
        self.assertTrue({"connections", "browser-code", "forms"} <= search_selection("all"))

    def test_browser_direct_sources_and_sinks(self):
        examples = [
            'panel.innerHTML=location.hash;',
            'panel.outerHTML="<div>"+window.location.search;',
            'document.write(document.referrer);',
            'panel.insertAdjacentHTML("beforeend",location.href);',
            'eval(location.hash);', 'new Function(location.search)();',
            'setTimeout(location.hash,0);',
            'localStorage.setItem("refresh_token",value);',
            'parent.postMessage(payload,"*");',
        ]
        for source in examples:
            with self.subTest(source=source):
                findings, _ = self.scan(source, {"browser-code"})
                self.assertTrue(findings)
                self.assertTrue(all(f.category == "Browser code" for f in findings))
                self.assertNotIn(source, str(findings))

    def test_browser_negative_controls(self):
        examples = [
            'panel.textContent=location.hash;',
            'panel.innerHTML=DOMPurify.sanitize(location.hash);',
            'panel.innerHTML="<strong>Safe text</strong>";',
            'const docs="eval(location.hash)";', '// document.write(location.hash);',
            'eval(location.hash === "#ready");',
            'setTimeout(()=>render(location.hash),0);',
            'parent.postMessage(payload,"https://trusted.invalid");',
            'localStorage.setItem("theme","dark");',
        ]
        for source in examples:
            with self.subTest(source=source):
                self.assertEqual(self.scan(source, {"browser-code"})[0], [])

    def test_inline_handlers_and_source_maps_preserve_locations(self):
        findings, _ = self.scan('<p>demo</p>\n<button onclick="eval(location.hash)">go</button>', {"browser-code"}, html=True)
        self.assertEqual(len(findings), 1)
        self.assertIn("Line 2", findings[0].evidence)
        findings, _ = self.scan(json.dumps({"sourcesContent": ['eval(location.hash);']}), {"browser-code"})
        self.assertTrue(any("Source-map source 0" in f.evidence for f in findings))

    def test_password_forms_overrides_and_mixed_content(self):
        html = '''<form action="/login" method="post"><input type="password" name="password">
        <button formaction="http://other.invalid/login" formmethod="get">go</button></form>
        <script src="http://assets.invalid/app.js"></script>'''
        findings, _ = self.scan(html, {"forms"}, html=True)
        self.assertEqual({f.title for f in findings}, {"Password form uses GET", "Password form submits over HTTP",
                         "Password form submits to another origin", "HTTP resource referenced by HTTPS page"})
        self.assertNotIn("other.invalid", str(findings))

    def test_forms_negative_controls(self):
        examples = ['<form action="/login" method="post"><input type="password" name="password"></form>',
                    '<form method="dialog"><input type="password" name="password"></form>',
                    '<form><input type="password" name="password" disabled></form>',
                    '<form><input type="password"></form>',
                    '<form><fieldset disabled><input type="password" name="password"></fieldset></form>',
                    '<form action="/search"><input name="q"></form>',
                    '<script src="https://assets.invalid/app.js"></script>']
        for html in examples:
            with self.subTest(html=html):
                self.assertEqual(self.scan(html, {"forms"}, html=True)[0], [])

    def test_resource_headers_check_cors_without_document_noise(self):
        response = requests.Response()
        response.url = "https://demo.invalid/config.json"
        response.headers.update({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        findings = analyze_headers(response, document=False)
        self.assertEqual([f.title for f in findings], ["Invalid credentialed wildcard CORS"])
        response.headers.clear()
        self.assertEqual(analyze_headers(response, document=False), [])

    def test_cookie_prefixes_and_server_disclosure(self):
        response = requests.Response()
        response.url = "https://demo.invalid/"
        response.headers.update({"Set-Cookie": "__Host-session=private-cookie-83; Path=/admin; Domain=demo.invalid",
                                 "Server": "demo/1.2.3"})
        findings = analyze_headers(response)
        self.assertIn("Invalid __Host- cookie prefix", {f.title for f in findings})
        self.assertIn("Server version disclosed", {f.title for f in findings})
        self.assertNotIn("private-cookie-83", str(findings))


if __name__ == "__main__":
    unittest.main()
