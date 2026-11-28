"""Independent syntax controls for report-driven precision improvements."""

import unittest

import requests

from gilbrt.headers import analyze_headers
from gilbrt.js_parser import candidates
from gilbrt.scanner import scan


class PrecisionRefinementTests(unittest.TestCase):
    url = "https://audit-fixture.invalid/a.js"

    def inspect(self, text, checks, html=False):
        values = []
        findings = scan(text, self.url, html, checks, lambda f, v: values.append(v))
        return findings, values

    def test_entropy_uses_live_sensitive_assignments_instead_of_example_text(self):
        value = "zY9!aB7@cD5#eF3$gH1%jK8&"
        for source, html in [(f'const token="{value}";',False),
                             ('{"credentials":{"secret":"'+value+'"}}',False),
                             (f'<script>const apiKey="{value}";</script>',True)]:
            with self.subTest(source=source):
                findings, values = self.inspect(source,{"entropy"},html)
                self.assertEqual(values,[value])
                self.assertNotIn(value,str(findings))
        for source, html in [(f'// const token="{value}";',False),
                             (f'/* token="{value}" */',False),
                             (f'const docs=\'const token="{value}";\';',False),
                             (f'<p>const token="{value}";</p>',True),
                             (f'<script>// const token="{value}";</script>',True)]:
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source,{"entropy"},html)[0],[])

    def test_outer_immutable_constants_resolve_without_ignoring_shadowing(self):
        source = 'const prefix="cross-scope-";function enter(){const password=prefix+"582391";}'
        findings, values = self.inspect(source,{"passwords"})
        self.assertEqual(values,["cross-scope-582391"])
        self.assertNotIn(values[0],str(findings))
        for body in ['function enter(prefix){const password=prefix+"582391";}',
                     'function enter(){let prefix=runtime();const password=prefix+"582391";}',
                     'function enter(){const password=prefix+"582391";let prefix=runtime();}',
                     'function enter(){if(flag){var prefix=runtime()}const password=prefix+"582391";}',
                     'function enter(){try{}catch(prefix){const password=prefix+"582391";}}',
                     'function enter(){eval(dynamic);const password=prefix+"582391";}']:
            with self.subTest(body=body):
                self.assertEqual(self.inspect('const prefix="outer-";'+body,{"passwords"})[0],[])

    def test_straight_line_mutation_reports_the_entire_current_value(self):
        for source, expected in [
            ('let part="mutable-";part+="739185";const password=part;',"mutable-739185"),
            ('let part="discarded-";part="replacement-739185";const password=part;',"replacement-739185"),
            ('var part="first-";part+="second-";part+="739185";const password=part;',"first-second-739185")]:
            with self.subTest(source=source):
                findings, values = self.inspect(source,{"passwords"})
                self.assertEqual(values,[expected]); self.assertNotIn(expected,str(findings))
        for source in [
            'let part="partial-";part+=runtime();const password=part;',
            'let part="partial-";if(flag)part+="suffix";const password=part;',
            'let part="partial-";mutate();const password=part;',
            'let part="partial-";function enter(){const password=part;}',
            'let part="partial-";for(let x of values)part+=x;const password=part;']:
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source,{"passwords"})[0],[])

    def test_unrelated_callback_cannot_enter_ai_review_pool(self):
        for source in ['dialog("Password",input=>other==="unrelated-credential-75");',
                       'dialog("Title",function(input){return other==="unrelated-credential-75"},true,"password");']:
            with self.subTest(source=source):
                self.assertEqual(candidates(source,review=True),[])
        self.assertTrue(candidates('dialog("Title",input=>input.trim()==="actual-input-75",true,"password");',review=True))

    def test_direct_local_function_arguments_reach_sinks_without_assuming_every_parameter_is_tainted(self):
        positive = 'function paint(content){panel.innerHTML=content}paint(location.hash);'
        self.assertTrue(self.inspect(positive,{"browser-code"})[0])
        for source in ['function paint(content){panel.innerHTML=content}paint("safe");',
                       'function paint(content){panel.innerHTML=content}',
                       'function paint(content){content="safe";panel.innerHTML=content}paint(location.hash);',
                       'function paint(content){panel.innerHTML=content}paint(DOMPurify.sanitize(location.hash));',
                       'function paint(content){panel.innerHTML=content}paint=another;paint(location.hash);',
                       'function paint(content){panel.innerHTML=content}queue(paint);',
                       'function paint(content){eval(dynamic);panel.innerHTML=content}paint(location.hash);']:
            with self.subTest(source=source):
                self.assertEqual(self.inspect(source,{"browser-code"})[0],[])

    def response(self, url, hsts=None):
        response = requests.Response(); response.url = url; response.status_code = 200
        if hsts is not None:
            response.headers["Strict-Transport-Security"] = hsts
        return response

    def test_hsts_is_evaluated_on_https_domain_hosts_and_not_repeated_on_http_pages(self):
        for url in ['http://audit-fixture.invalid/','http://127.0.0.1/','https://127.0.0.1/','https://[::1]/']:
            with self.subTest(url=url):
                self.assertNotIn('Missing Strict-Transport-Security',[f.title for f in analyze_headers(self.response(url))])
        self.assertIn('Missing Strict-Transport-Security',[f.title for f in analyze_headers(self.response('https://audit-fixture.invalid/'))])
        findings = analyze_headers(self.response('http://audit-fixture.invalid/','max-age=123'))
        self.assertIn('HSTS sent over HTTP',[f.title for f in findings])
        self.assertNotIn('Weak HSTS policy',[f.title for f in findings])

    def test_very_large_hsts_age_cannot_crash_the_audit(self):
        findings = analyze_headers(self.response('https://audit-fixture.invalid/','max-age='+'9'*5000))
        self.assertNotIn('Weak HSTS policy',[f.title for f in findings])
        findings = analyze_headers(self.response('https://audit-fixture.invalid/','max-age='+'0'*5000+'100'))
        self.assertIn('Weak HSTS policy',[f.title for f in findings])


if __name__ == '__main__':
    unittest.main()
