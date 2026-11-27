"""Reproducible loopback-only accuracy benchmark; never contacts a public target.

Run: python -m scripts.benchmark_demo [--with-ai] [--output-dir PATH]
Ground truth is defined before scanning. Scores count cases, not duplicate findings.
This is a synthetic development benchmark, not independent scanner certification.
"""

import argparse
import contextlib
import io
import json
import os
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from gilbrt.cli import main as audit
from gilbrt.scanner import safe_url


@dataclass(frozen=True)
class Case:
    name: str
    body: str
    category: str | None
    note: str = ""
    kind: str = "application/javascript"


CASES = [
    Case("password-assignment", 'const password="demo-sunrise-73";', "Password"),
    Case("prefixed-password", 'const dbPassword="demo-database-28";', "Password"),
    Case("numeric-pin", 'if(pin===7392) unlock();', "Access code"),
    Case("reverse-gate", 'if("demo-gate-62"===accessCode) unlock();', "Access code"),
    Case("minified-gate", 'x==="demo-minified-91"&&unlock()', "Access code"),
    Case("ternary-gate", 'accessCode==="demo-ternary-84"?unlock():deny()', "Access code"),
    Case("password-comparison", 'if(password==="demo-login-36") login();', "Password"),
    Case("prefilled-password", '<input type="password" value="demo-field-82">', "Password", kind="text/html"),
    Case("data-password", '<div data-password="demo-data-23"></div>', "Password", kind="text/html"),
    Case("visible-password", '<p>Password: demo-visible-94</p>', "Password", kind="text/html"),
    Case("json-password", '{"password":"demo-config-47"}', "Password", kind="application/json"),
    Case("source-map-password", json.dumps({"version": 3, "sources": ["src.js"], "sourcesContent": ['const password="demo-map-58";']}), "Password", kind="application/json"),
    Case("openai-shaped", 'const key="sk-proj-DemoOnlyA8b7C6d5E4f3G2h1J0k9";', "Secret"),
    Case("aws-shaped", 'const key="AKIA1234567890ABCDEF";', "Secret"),
    Case("github-shaped", 'const key="ghp_DemoOnlyA8b7C6d5E4f3G2h1J0k9";', "Secret"),
    Case("stripe-shaped", 'const key="sk_live_DemoOnlyA8b7C6d5E4f3";', "Secret"),
    Case("anthropic-shaped", 'const key="sk-ant-DemoOnlyA8b7C6d5E4f3G2h1J0k9";', "Secret"),
    Case("google-shaped", 'const key="AIza' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r' + '";', "Secret"),
    Case("private-key-marker", 'const pem="-----BEGIN PRIVATE KEY-----\\nDEMO-NOT-A-REAL-KEY";', "Secret"),
    Case("jwt-shaped", 'const token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZW1vIn0.DemoSignatureOnly123456";', "Secret"),
    Case("plaintext-password", 'password: demo-plaintext-68', "Password", kind="text/plain"),
    # These are client-side secret exposures too, although documented static limitations apply.
    Case("split-password", 'const password="demo-"+"split-76";', "Password", "Concatenation requires reconstruction; a fragment alone is not a complete credential."),
    Case("encoded-password", 'const password=atob("ZGVtby1lbmNvZGVkLTQ5");', "Password", "Requires decoding/data flow."),
    Case("computed-gate", 'const digits=[4,8,2,7]; if(pin===digits.join("")) unlock();', "Access code", "Requires evaluating the computed comparison value."),
    Case("runtime-secret", 'fetch("/unlinked-runtime-secret").then(r=>r.json()).then(c=>window.password=c.password);', "Password", "Secret exists only in an unlinked runtime response; passive crawler does not execute fetch."),
    Case("ordinary-heading", 'const heading="Welcome to the demo";', None),
    Case("environment-password", 'const password=process.env.DB_PASSWORD;', None),
    Case("variable-reference", 'const password=getPassword();', None),
    Case("placeholder", 'const password="YOUR_PASSWORD_HERE";', None),
    Case("masked-password", 'const password="********";', None),
    Case("empty-password", 'const password="";', None),
    Case("comment-example", '// const password="docs-example-12";', None),
    Case("quoted-example", 'const docs=\'const password="docs-example-34";\';', None),
    Case("status-comparison", 'if(status==="success") showToast();', None),
    Case("keyboard-code", 'if(event.code==="Enter") submit();', None),
    Case("http-code", 'if(response.code===200) render();', None),
    Case("ui-label", 'const passwordLabel="Enter your password";', None),
    Case("dynamic-template", 'const password=`${userInput}`;', None),
    Case("password-field-empty", '<input type="password" name="password" value="">', None, kind="text/html"),
    Case("color-token", 'const token="blue";', None),
    Case("ordinary-code", 'const code="USD"; if(code==="USD") formatCurrency();', None),
    Case("public-example-key", 'const key="sk-proj-DocumentationExampleOnly123456789";', None, "Explicitly public example; token shape alone cannot establish a real secret."),
]

EXTENDED_CASES = [
    Case("database-url", 'const database="postgresql://demo:demo-db-91@db.invalid/demo";', "Connection"),
    Case("redis-url", 'const cache="redis://demo:demo-cache-82@cache.invalid:6379/0";', "Connection"),
    Case("mongodb-url", 'const database="mongodb+srv://demo:demo-mongo-73@db.invalid/demo";', "Connection"),
    Case("http-userinfo", 'const service="https://demo:demo-http-64@api.invalid";', "Connection"),
    Case("dom-html", 'panel.innerHTML=location.hash;', "Browser code"),
    Case("dom-document-write", 'document.write(location.search);', "Browser code"),
    Case("dom-eval", 'eval(location.hash);', "Browser code"),
    Case("dom-function", 'new Function(location.hash)();', "Browser code"),
    Case("dom-insert", 'panel.insertAdjacentHTML("beforeend", location.search);', "Browser code"),
    Case("dom-outer-html", 'panel.outerHTML=`<div>${location.hash}</div>`;', "Browser code"),
    Case("wildcard-message", 'window.parent.postMessage(payload,"*");', "Browser code", "Review candidate; message may be intentionally public."),
    Case("token-storage", 'localStorage.setItem("access_token", token);', "Browser code", "Review candidate; storage suitability depends on the credential model."),
    Case("password-get-form", '<form action="/login"><input type="password" name="password"></form>', "Form", kind="text/html"),
    Case("password-http-form", '<form action="http://auth.invalid/login" method="post"><input type="password" name="password"></form>', "Form", kind="text/html"),
    Case("password-button-override", '<form action="/login" method="post"><input type="password" name="password"><button formmethod="get">Login</button></form>', "Form", kind="text/html"),
    Case("charcode-password", 'const password=String.fromCharCode(100,101,109,111,45,57,50);', "Password"),
    Case("literal-joined-gate", 'if(pin===[4,2,8,6].join("")) unlock();', "Access code"),
    Case("const-concat-password", 'const prefix="demo-";const password=prefix+"assembled-53";', "Password"),
    Case("safe-text-content", 'panel.textContent=location.hash;', None),
    Case("sanitized-html", 'panel.innerHTML=DOMPurify.sanitize(location.hash);', None),
    Case("static-html", 'panel.innerHTML="<strong>Welcome</strong>";', None),
    Case("quoted-dom-example", 'const docs="panel.innerHTML=location.hash";', None),
    Case("commented-eval", '// eval(location.hash);', None),
    Case("callback-timer", 'setTimeout(()=>render(location.hash),100);', None),
    Case("restricted-message", 'window.parent.postMessage(payload,"https://trusted.invalid");', None),
    Case("preference-storage", 'localStorage.setItem("theme","dark");', None),
    Case("password-free-connection", 'const database="postgresql://db.invalid/demo";', None),
    Case("placeholder-connection", 'const database="postgresql://user:YOUR_PASSWORD_HERE@db.invalid/demo";', None),
    Case("post-https-form", '<form action="https://127.0.0.1/login" method="post"><input type="password" name="password"></form>', "Form", "Cross-origin destination remains a review candidate.", kind="text/html"),
    Case("nonpassword-get-form", '<form action="/search"><input name="q"></form>', None, kind="text/html"),
    Case("dialog-password-form", '<form method="dialog"><input type="password"></form>', None, kind="text/html"),
]

# Additional cases fixed before the second refinement run. These intentionally
# include unsupported behavior and harmless UI text; failures stay in the score.
CHALLENGE_CASES = [
    Case("validator-return", 'function verifyInvitation(value){return value === "invite-river-93";}', "Access code"),
    Case("early-return-auth", 'function checkAccess(v){if(v !== "permit-stone-62") return false; return true;}', "Access code"),
    Case("minified-return", 'function authenticate(e){return e==="entry-willow-81"}', "Access code"),
    Case("unfamiliar-access-action", 'if(enteredValue === "entry-maple-28") revealProtectedPanel();', "Access code"),
    Case("switch-gate", 'switch(accessCode){case "switch-cedar-57":unlock();break;}', "Access code"),
    Case("password-suffix-name", 'const passwordValue="suffix-elm-46";', "Password"),
    Case("password-secret-name", 'const loginPasswordHash="not-a-plaintext-password";', None, "A hash-labeled value is not a plaintext credential."),
    Case("hydration-json", '<script type="application/json">{"credentials":{"password":"hydration-ash-39"}}</script>', "Password", kind="text/html"),
    Case("encoded-provider-key", 'const apiKey=atob("c2stcHJvai1BYmMxMjNEZWY0NTZHaGk3ODlKa2wwMTI=");', "Secret"),
    Case("split-provider-key", 'const apiKey="sk-proj-"+"Abc123Def456Ghi789Jkl012";', "Secret"),
    Case("source-before-sink", 'const query=location.hash; document.getElementById("result").innerHTML=query;', "Browser code"),
    Case("destructured-source", 'const {hash}=location; result.innerHTML=hash;', "Browser code"),
    Case("search-params-source", 'const query=new URLSearchParams(location.search).get("q"); result.innerHTML=query;', "Browser code"),
    Case("runtime-gap", 'fetch("/unlinked-runtime-secret").then(r=>r.json()).then(c=>window.password=c.password);', "Password"),
    Case("cross-block-secret", 'const prefix="outer-"; function login(){const password=prefix+"beech-45";}', "Password", "Cross-scope reconstruction remains outside bounded folding."),
    Case("label-help-text", '<label>Password:</label><input type="password"><a>Forgot password?</a>', None, kind="text/html"),
    Case("password-instructions", '<p>Password: must contain at least eight characters</p>', None, kind="text/html"),
    Case("password-validation-message", '<div>Password: invalid. Please try again.</div>', None, kind="text/html"),
    Case("separate-help-blocks", '<div>Password:</div><div>Reset your password here</div>', None, kind="text/html"),
    Case("ui-return", 'function chooseTheme(v){return v === "midnight";}', None),
    Case("route-return", 'function isHome(v){return v === "/home";}', None),
    Case("content-type-return", 'function accepts(v){return v === "application/json";}', None),
    Case("sanitized-alias", 'const query=DOMPurify.sanitize(location.hash); result.innerHTML=query;', None),
    Case("overwritten-alias", 'let query=location.hash; query="<b>Safe</b>";result.innerHTML=query;', None),
    Case("function-boundary-alias", 'const query=location.hash; function display(query){result.innerHTML=query;}', None),
    Case("commented-source-alias", '// const query=location.hash;\nresult.innerHTML="<b>Safe</b>";', None),
    Case("provider-documentation", '<pre>Example: sk-proj-DocumentationExampleOnly123456789</pre>', None, "Provider-shaped public examples may remain false alarms.", kind="text/html"),
]

# A separate variant set used only after the refinement changes, not for the
# before/after comparison. Keep missed/unsupported cases in its denominator too.
HOLDOUT_CASES = [
    Case("account-password-value", 'const accountPasswordValue="holdout-fern-91";', "Password"),
    Case("prefixed-pwd-value", 'const DB_PWD_VALUE="holdout-spruce-82";', "Password"),
    Case("password-array-json", '<script type="application/json">{"users":[{"passwordValue":"holdout-birch-73"}]}</script>', "Password", kind="text/html"),
    Case("concatenated-token", 'const accessToken="ghp_"+"Abc123Def456Ghi789Jkl012";', "Secret"),
    Case("arrow-validator", 'const validateInvitation = input => input === "holdout-larch-64";', "Access code"),
    Case("return-validator", 'function validateAdminLogin(s){return s === "holdout-pine-55";}', "Access code"),
    Case("switch-pin", 'switch(settings.pin){case "holdout-alder-46":unlock();break;}', "Access code"),
    Case("aliased-search", 'const term=new URLSearchParams(location.search).get("term");document.write(term);', "Browser code"),
    Case("outer-binding-gap", 'const prefix="holdout-";function enter(){const password=prefix+"fir-37";}', "Password"),
    Case("runtime-gap", 'fetch("/unlinked-runtime-secret").then(r=>r.json()).then(x=>window.password=x.password);', "Password"),
    Case("password-helper", '<label>Password:</label><a>Show password</a>', None, kind="text/html"),
    Case("password-rule", '<p>Password: choose a unique phrase for this account</p>', None, kind="text/html"),
    Case("password-hash-metadata", 'const config={passwordHash:"a-fake-digest",passwordLength:16};', None),
    Case("locale-predicate", 'const chooseLocale=v=>v === "en-GB";', None),
    Case("sidebar-predicate", 'const isSidebarExpanded=v=>v === "expanded";', None),
    Case("sanitizer-alias", 'const html=DOMPurify.sanitize(location.search);panel.outerHTML=html;', None),
    Case("mutable-overwrite", 'let html=location.search;html="ready";document.write(html);', None),
    Case("environment-config", 'const passwordValue=import.meta.env.ADMIN_PASSWORD;', None),
    Case("quoted-validator", 'const docs="function login(v){return v===\'demo-only\';}";', None),
    Case("public-key-fixture", 'const key="sk-proj-DocumentationExampleOnly123456789";', None, "Provider-shaped public example remains a potential false alarm."),
]

HEADER_CASES = {
    "missing-csp": ({"Content-Security-Policy": None}, "Missing Content-Security-Policy"),
    "permissive-csp": ({"Content-Security-Policy": "script-src * 'unsafe-inline'"}, "Permissive script CSP"),
    "invalid-frame": ({"X-Frame-Options": "ALLOWALL"}, "Invalid X-Frame-Options"),
    "invalid-nosniff": ({"X-Content-Type-Options": "wrong"}, "Invalid X-Content-Type-Options"),
    "weak-cookie": ({"Set-Cookie": "session=demo-only; SameSite=None"}, "Cookie missing defenses"),
    "weak-referrer": ({"Referrer-Policy": "unsafe-url"}, "Review Referrer-Policy"),
    "secure-control": ({}, None),
    "cors-wildcard-credentials": ({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, "Invalid credentialed wildcard CORS"),
    "cors-null": ({"Access-Control-Allow-Origin": "null"}, "CORS trusts null origin"),
    "server-version": ({"Server": "demo-server/1.2.3"}, "Server version disclosed"),
    "host-cookie-prefix": ({"Set-Cookie": "__Host-session=demo; Secure; HttpOnly; SameSite=Strict; Path=/account; Domain=demo.invalid"}, "Invalid __Host- cookie prefix"),
    "secure-cookie-prefix": ({"Set-Cookie": "__Secure-session=demo; HttpOnly; SameSite=Strict"}, "Invalid __Secure- cookie prefix"),
    "cors-public-control": ({"Access-Control-Allow-Origin": "*"}, None),
    "cors-specific-control": ({"Access-Control-Allow-Origin": "https://trusted.invalid", "Vary": "Origin"}, None),
    "host-cookie-control": ({"Set-Cookie": "__Host-session=demo; Secure; HttpOnly; SameSite=Strict; Path=/"}, None),
}
SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=()",
}
MARKER = "DEMO_SYNTHETIC_PRIVATE_RECORD_89241"


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "GilbrtDemo"
    sys_version = ""
    visits: list[str] = []
    cases = CASES

    def log_message(self, *_):
        pass

    def do_GET(self):
        path = urlsplit(self.path).path
        self.visits.append(path)
        headers = {}
        kind = "text/html"
        if path == "/robots.txt":
            body, kind = "User-agent: *\nAllow: /\n", "text/plain"
        elif path == "/":
            body = '<h1>Gilbrt synthetic vulnerability laboratory</h1>'
            body += ''.join(f'<a href="/case/{c.name}">{c.name}</a> ' for c in self.cases)
            body += ''.join(f'<a href="/headers/{name}">{name}</a> ' for name in HEADER_CASES)
        elif path.startswith("/case/"):
            case = next((c for c in self.cases if path == "/case/" + c.name), None)
            if not case:
                self.send_error(404)
                return
            body, kind = case.body, case.kind
        elif path.startswith("/headers/") and path.rsplit("/", 1)[1] in HEADER_CASES:
            headers = HEADER_CASES[path.rsplit("/", 1)[1]][0]
            body = "<p>Synthetic browser defense test</p>"
        elif path == "/unlinked-runtime-secret":
            body, kind = '{"password":"demo-runtime-92"}', "application/json"
        elif path in {"/record/exposed", "/record/protected"}:
            owner = self.headers.get("Authorization") == "Bearer demo-owner"
            if path.endswith("protected") and not owner:
                self.send_error(403)
                return
            body, kind = json.dumps({"record": MARKER}), "application/json"
        else:
            self.send_error(404)
            return
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", kind + "; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        for key, value in {**SECURE_HEADERS, **headers}.items():
            if value is not None:
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(encoded)


def score(report, origin, cases=CASES):
    rows = []
    for case in cases:
        findings = [f for f in report["findings"] if f["url"] == safe_url(origin + "/case/" + case.name)
                    and f["category"] in {"Password", "Access code", "Secret", "Local AI", "Connection", "Browser code", "Form", "Mixed content"}]
        expected = case.category
        detected = any(f["category"] == expected or (expected == "Access code" and f["category"] == "Local AI") for f in findings) if expected else bool(findings)
        outcome = ("TP" if detected else "FN") if expected else ("FP" if detected else "TN")
        rows.append({"case": case.name, "expected": expected, "outcome": outcome,
                     "note": case.note, "findings": findings})
    counts = {key: sum(r["outcome"] == key for r in rows) for key in ("TP", "FN", "FP", "TN")}
    tp, fn, fp, tn = (counts[k] for k in ("TP", "FN", "FP", "TN"))
    headers = []
    for name, (_, expected) in HEADER_CASES.items():
        titles = [f["title"] for f in report["findings"] if f["url"] == safe_url(origin + "/headers/" + name)
                  and f["category"] == "Headers" and f["title"] != "Missing Strict-Transport-Security"]
        headers.append({"case": name, "expected_title": expected, "titles": titles,
                        "passed": expected in titles if expected else not titles})
    active = [f for f in report["findings"] if f["category"] == "AI isolation"]
    return {"counts": counts, "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None,
            "cases": rows, "header_cases": headers, "active_isolation": active,
            "active_checks_passed": len(active) == 4 and sum(f["severity"] == "Critical" for f in active) == 2
                and all(f["severity"] != "Critical" for f in active if f["url"] == safe_url(origin + "/record/protected")),
            "metadata": report["metadata"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--with-ai", action="store_true")
    parser.add_argument("--extended", action="store_true", help="Include connection, browser-code and form cases")
    parser.add_argument("--challenge", action="store_true", help="Use the harder refinement corpus instead of the original cases")
    parser.add_argument("--holdout", action="store_true", help="Use the separate post-refinement variant corpus")
    parser.add_argument("--output-dir", default=".runtime/demo-benchmark")
    args = parser.parse_args()
    cases = HOLDOUT_CASES if args.holdout else CHALLENGE_CASES if args.challenge else CASES + EXTENDED_CASES if args.extended else CASES
    DemoHandler.cases = cases
    destination = Path(args.output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    config = {"environment": "local", "isolation": [
        {"path": "/record/" + mode, "synthetic": True, "marker": MARKER,
         "owner_token_env": "GILBRT_DEMO_OWNER", "other_token_env": "GILBRT_DEMO_OTHER"}
        for mode in ("exposed", "protected")]}
    config_path = destination / "active-config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    names = ("GILBRT_DEMO_OWNER", "GILBRT_DEMO_OTHER")
    prior = {name: os.environ.get(name) for name in names}
    os.environ.update(dict(zip(names, ("demo-owner", "demo-other"))))
    results = {"limitations": [
        "Synthetic hand-authored cases; no general real-world accuracy claim.",
        "Case-level content precision/recall; duplicate observations do not increase score.",
        "Header and configured isolation checks scored separately. Missing HSTS excluded on loopback HTTP.",
        "Provider-shaped dummy strings test detection, not credential validity; private key is only a marker.",
        "Scores measure candidate detection, not recovery of complete secrets; split-password may report only a fragment.",
        "No SQL injection, XSS exploit, real TLS certificate, HIBP, or real model prompt-boundary benchmark."]}
    try:
        for mode in (["static", "static-plus-ai"] if args.with_ai else ["static"]):
            print(f"Running {mode} against {len(cases)} content cases, {len(HEADER_CASES)} header cases and 4 isolation checks...", flush=True)
            DemoHandler.visits.clear()
            report_path = destination / f"{mode}.json"
            command = ["--url", origin, "--confirm-authorized", "--rate-limit", "0", "--max-pages", "100",
                       "--max-depth", "2", "--search", "passwords,access-codes,api-keys,tokens,private-keys,headers,connections,browser-code,forms",
                       "--active", "--active-config", str(config_path), "--output", str(report_path)]
            if mode.endswith("ai"):
                command += ["--local-model", "bundled", "--ai-max-batches", "0"]
            started = time.monotonic()
            log = io.StringIO()
            with contextlib.redirect_stdout(log):
                code = audit(command)
            (destination / f"{mode}.log").write_text(log.getvalue(), encoding="utf-8")
            if code:
                raise RuntimeError(f"{mode} audit exited {code}; see log")
            result = score(json.loads(report_path.read_text(encoding="utf-8")), origin, cases)
            result["elapsed_seconds"] = round(time.monotonic() - started, 2)
            result["runtime_endpoint_requested"] = "/unlinked-runtime-secret" in DemoHandler.visits
            result["all_case_resources_scanned"] = all(safe_url(origin + "/case/" + c.name) in
                {r["resource"] for r in result["metadata"]["resource_inventory"]} for c in cases)
            results[mode] = result
            if mode == "static-plus-ai":
                baseline = {row["case"]: row["outcome"] for row in results["static"]["cases"]}
                result["ai_incremental"] = {
                    "new_true_positive_cases": [row["case"] for row in result["cases"] if row["outcome"] == "TP" and baseline[row["case"]] == "FN"],
                    "new_false_positive_cases": [row["case"] for row in result["cases"] if row["outcome"] == "FP" and baseline[row["case"]] == "TN"],
                }
            print(json.dumps({"mode": mode, "counts": result["counts"], "precision": result["precision"],
                              "recall": result["recall"], "elapsed_seconds": result["elapsed_seconds"]}), flush=True)
            (destination / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        for name, value in prior.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    print(f"Results: {destination / 'results.json'}")


if __name__ == "__main__":
    main()
