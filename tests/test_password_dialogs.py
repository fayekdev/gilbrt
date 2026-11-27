"""Regression for unnamed password-dialog callbacks and misleading AI predicates."""

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gilbrt.crawler import ScopedClient
from gilbrt.js_parser import candidates
from gilbrt.scanner import scan


class PasswordDialogTests(unittest.TestCase):
    def inspect(self, source, html=False):
        values = []
        findings = scan(source, "https://fixture.invalid/", html=html, checks={"passwords", "access-codes"},
                        on_secret=lambda finding, value: values.append(value))
        return findings, values

    def test_custom_password_dialog_callback_and_state_assignment(self):
        source = '''function toggle(){
          dialog(lang==="ar"?"رمز الإدارة":"Admin code","",v=>{
            if(v.trim()=="dialog-fixture-7193"){OWNER=true;store.set("owner",true);draw()}
            else return "Wrong code";
          },true,"password");
        }'''
        findings, values = self.inspect(source)
        self.assertEqual(values, ["dialog-fixture-7193"])
        self.assertEqual(findings[0].category, "Password")
        self.assertIn("password-input callback", findings[0].evidence)
        self.assertNotIn("dialog-fixture-7193", str(findings))

    def test_function_callback_reversed_comparison_and_access_code_label(self):
        for source, expected, category in [
            ('dialog("Title","",function(v){return "function-fixture-82"===v.trim()},true,"password");', "function-fixture-82", "Password"),
            ('dialog("Access code",v=>v==="code-fixture-64");', "code-fixture-64", "Access code"),
        ]:
            with self.subTest(source=source):
                findings, values = self.inspect(source)
                self.assertEqual(values, [expected])
                self.assertEqual(findings[0].category, category)

    def test_dialog_rule_requires_its_parameter_and_credential_context(self):
        sources = [
            'dialog("Title","",v=>v.trim()==="ordinary-text",true,"text");',
            'dialog("Title","",v=>other==="unrelated-value",true,"password");',
            'dialog("Title","",v=>v.length===4,true,"password");',
            'const passwordLabel="password";dialog("Title",v=>v==="ordinary-text");',
            '[1,2].filter(v=>v==="ordinary-text","password");',
            'dialog("Title","",v=>{function check(x){return x==="unrelated-value"}},true,"password");',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source)[0], [])

    def test_ai_pool_excludes_collection_statuses_and_template_rendering(self):
        sources = [
            'const count=values.filter(x=>x==="present").length;',
            'const choose=b=>state==="done"||(state==="prog"?b.n>0:b.n===0);',
            'const render=v=>`<button class="${v==="custom-style"?"active":""}">Go</button>`;',
            'const matches=rows.some(x=>x==="some-label");',
        ]
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(candidates(source, include_password_assignments=True, review=True), [])
        self.assertTrue(candidates('if(password==="present") unlock();', review=True))
        self.assertTrue(candidates('function validateInvitation(v){return v==="validator-fixture-53"}', review=True))

    def test_large_embedded_asset_does_not_hide_password_callback(self):
        source = '<script>const image="' + 'A' * 150000 + '";</script>\n<script>dialog("Admin code","",v=>{if(v.trim()=="large-fixture-93")owner=true},true,"password");</script>'
        findings, values = self.inspect(source, html=True)
        self.assertEqual(values, ["large-fixture-93"])
        self.assertIn("Line 2", findings[0].evidence)

    def test_html_declared_charset_preserves_non_ascii_password(self):
        body = '<meta charset="utf-8"><script>const password="كلمة-اختبار-73";</script>'.encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        client = ScopedClient(f"http://127.0.0.1:{server.server_port}/", delay=0)
        try:
            response = client.get(client.target)
            self.assertIsNotNone(response)
            self.assertEqual(self.inspect(response.text, html=True)[1], ["كلمة-اختبار-73"])
        finally:
            client.session.close()
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    unittest.main()
