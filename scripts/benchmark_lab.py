"""Seeded loopback integration lab with exact-value scoring and explicit misses.

python -m scripts.benchmark_lab --with-ai
python -m scripts.benchmark_lab --serve --port 8765
Generated sources contain inert synthetic credentials. Never deploy this lab.
"""

import argparse
import base64
import hashlib
import html
import json
import os
import random
import re
import threading
import time
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from gilbrt.cli import parser as audit_parser, run_audit
from gilbrt.reporter import report_document, render_report
from gilbrt.scanner import safe_url

CONTENT_CATEGORIES = {"Password", "Access code", "Secret", "Connection", "Browser code", "Form", "Mixed content", "Local AI"}
CHECKS = {"passwords", "access-codes", "api-keys", "tokens", "private-keys", "entropy", "connections", "browser-code", "forms", "headers"}
MARKER = "GILBRT_LAB_SYNTHETIC_PRIVATE_RECORD_2026"
TEST_ENV = {"GILBRT_LAB_OWNER": "lab-owner-only", "GILBRT_LAB_OTHER": "lab-other-only", "GILBRT_LAB_CHAT": "lab-chat-only"}


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Case:
    name: str
    path: str
    category: str | None
    fingerprint: str | None = None
    title: str | None = None
    requirement: str = ""


class Lab:
    def __init__(self, seed=20261127):
        self.seed = seed
        self.random = random.Random(seed)
        self.routes = {}
        self.cases = []
        self.entry_imports = []
        self.pages = []
        self.header_cases = []
        self.visits = []
        self.lock = threading.Lock()
        self.trap_hits = 0
        self.build()

    def token(self):
        return "lab-" + "".join(self.random.choice("abcdefhijkmnpqrstuvwxy23456789") for _ in range(19))

    def route(self, path, body, kind="application/javascript", headers=None):
        self.routes[path] = (body.encode("utf-8"), kind, headers or {})

    def case(self, name, body, category, value=None, title=None, requirement="", kind="application/javascript", linked=True):
        extension = ".html" if kind == "text/html" else ".json" if kind == "application/json" else ".js"
        path = "/modules/" + self.token() + extension
        self.route(path, body, kind)
        self.cases.append(Case(name, path, category, digest(value) if value is not None else None, title, requirement))
        if linked:
            (self.pages if kind == "text/html" else self.entry_imports).append(path)
        return path

    def secret(self, name, template, category="Password", requirement="constant credential", **kwargs):
        value = self.token()
        return self.case(name, template(value), category, value=value, requirement=requirement, **kwargs)

    def build(self):
        self.secret("custom-password-dialog", lambda v: f'function gate(){{edit("Admin code","",x=>{{if(x.trim()==="{v}"){{OWNER=true;draw()}}}},true,"password")}}', requirement="unnamed callback, trim, password input, boolean state")
        self.secret("reversed-dialog", lambda v: f'edit("Title","",function(z){{return "{v}"===z.trim()}},true,"password")', requirement="function callback and reversed comparison")
        value = "تجربة-" + self.token()
        self.case("unicode-json", '<meta charset="utf-8"><script type="application/json">'+json.dumps({"users": [{"adminPasswordValue": value}]}, ensure_ascii=False)+'</script>', "Password", value=value, kind="text/html", requirement="HTML charset and nested JSON hydration")
        self.secret("split-password", lambda v: f'const password="{v[:9]}"+"{v[9:]}";', requirement="reconstruct entire secret, not a fragment")
        self.secret("base64-password", lambda v: 'const password=atob('+json.dumps(base64.b64encode(v.encode()).decode())+');', requirement="literal base64 reconstruction")
        self.secret("joined-pin", lambda v: 'if(accessCode==='+json.dumps(list(v))+'.join("")) unlock();', category="Access code", requirement="array join reconstruction")
        self.secret("named-switch", lambda v: f'switch(settings.accessCode){{case "{v}":unlock();break}}', category="Access code", requirement="switch literal and property subject")
        self.secret("arrow-validator", lambda v: f'const validateInvitation=input=>input==="{v}";', category="Access code", requirement="AI-only returning validator")
        self.secret("early-return", lambda v: f'function verifyAccess(v){{if(v!=="{v}")return false;return true}}', category="Access code", requirement="AI-only rejection branch")
        self.secret("large-script", lambda v: 'const image="'+'A'*(1100*1024)+f'";const adminPassword="{v}";', requirement="credential after >1 MiB embedded asset")
        self.secret("cross-scope", lambda v: f'const prefix="{v[:8]}";function login(){{const password=prefix+"{v[8:]}";}}', requirement="cross-scope constant propagation; known hard case")
        self.secret("mutable-dataflow", lambda v: f'let part="{v[:8]}";part+="{v[8:]}";const password=part;', requirement="mutable reconstruction; known hard case")
        value = "ghp_" + self.token().replace("-", "") + "A1b2C3d4"
        self.case("encoded-provider", 'const accessToken=atob('+json.dumps(base64.b64encode(value.encode()).decode())+');', "Secret", value=value, requirement="encoded provider-shaped inert token")
        value = "postgresql://demo:" + self.token() + "@database.invalid/lab"
        self.case("database-url", 'const database='+json.dumps(value)+';', "Connection", value=value, requirement="credential-bearing URI; no database connection")
        self.secret("generic-sensitive-token", lambda v:'const token='+json.dumps(v)+';', category="Secret", requirement="high-entropy sensitive assignment")

        # A literal lives in one module and is imported/compared in another.
        value = self.token()
        part = "/modules/" + self.token() + ".js"
        self.route(part, 'export const expected='+json.dumps(value)+';')
        self.case("cross-module", f'import {{expected}} from "{part}";export function validatePassword(v){{return v===expected;}}', "Password", value=value, requirement="cross-file data flow; known hard case")

        runtime_value = self.token()
        runtime_path = self.case("runtime-only-api", json.dumps({"password": runtime_value}), "Password", value=runtime_value,
                                 kind="application/json", linked=False, requirement="unlinked runtime fetch; requires explicitly supplied URL")
        self.runtime_path = runtime_path
        self.route("/runtime-loader.js", 'fetch('+json.dumps(runtime_path)+').then(r=>r.json()).then(v=>window.current=v);')
        self.entry_imports.append("/runtime-loader.js")

        # Deep document, iframe, CSS map and sitemap paths cannot be found from
        # direct homepage links to every case.
        deep_path = self.secret("deep-document", lambda v: f'<script>const password="{v}";</script>', kind="text/html", linked=False, requirement="three document hops")
        self.route("/level/one", '<a href="/level/two">Continue</a>', "text/html")
        self.route("/level/two", f'<a href="{deep_path}">Continue</a>', "text/html")
        frame_path = self.secret("iframe-password", lambda v: f'<script>const password="{v}";</script>', kind="text/html", linked=False, requirement="iframe discovery")
        self.frame_path = frame_path
        map_path = self.secret("decoded-source-map", lambda v: json.dumps({"version": 3, "sources": ["original.ts"], "sourcesContent": [f'const password="{v}";']}), kind="application/json", linked=False, requirement="CSS import then referenced sourcesContent")
        self.route("/styles/lab.css", '@import "./theme.css";', "text/css")
        self.route("/styles/theme.css", '/*# sourceMappingURL='+map_path+' */', "text/css")
        sitemap_path = self.secret("sitemap-only", lambda v: f'<script>const password="{v}";</script>', kind="text/html", linked=False, requirement="robots-declared sitemap discovery")
        self.route("/pages.xml", '<urlset><url><loc>'+sitemap_path+'</loc></url></urlset>', "application/xml")
        self.sitemap_path = sitemap_path

        dom_cases = [
            ("direct-dom-source", 'panel.innerHTML=location.hash;', "Browser input assigned to HTML sink"),
            ("const-alias-dom", 'const raw=location.search;panel.innerHTML=raw;', "Browser input assigned to HTML sink"),
            ("url-params-dom", 'const q=new URLSearchParams(location.search).get("q");document.write(q);', "Browser input reaches document.write"),
            ("two-step-alias", 'const a=location.hash;const b=a;panel.outerHTML=b;', "Browser input assigned to HTML sink"),
            ("function-flow-dom", 'function render(value){panel.innerHTML=value}render(location.hash);', "Browser input assigned to HTML sink"),
        ]
        for name, source, title in dom_cases:
            self.case(name, source, "Browser code", title=title, requirement="browser-input flow; syntax finding, not XSS exploitation")
        self.case("insecure-password-form", '<form action="http://auth.invalid/login"><input type="password" name="password"></form>', "Form", title="Password form uses GET", kind="text/html", requirement="password form transport and method")
        self.case("submit-button-override", '<form action="/login" method="post"><input type="password" name="password"><button formmethod="get">Login</button></form>', "Form", title="Password form uses GET", kind="text/html", requirement="button overrides secure form defaults")

        negatives = [
            ("status-filter", 'const count=rows.filter(v=>v==="present").length;'),
            ("status-render", 'const view=v=>`<p class="${v==="done"?"active":""}">Done</p>`;'),
            ("generic-theme", 'const chooseTheme=v=>v==="midnight";'),
            ("password-comment", '// const password="comment-only-credential";'),
            ("quoted-password", 'const docs=\'const password="quoted-only-credential";\';'),
            ("environment-reference", 'const adminPasswordValue=import.meta.env.ADMIN_PASSWORD;'),
            ("masked-value", 'const password="********";'),
            ("hash-metadata", 'const account={passwordHash:"digest-only",passwordLength:16};'),
            ("sanitized-dom", 'const value=DOMPurify.sanitize(location.hash);panel.innerHTML=value;'),
            ("overwrite-dom", 'let value=location.hash;value="safe";panel.innerHTML=value;'),
            ("shadowed-dom", 'const value=location.hash;function render(value){panel.innerHTML=value}'),
            ("text-sink", 'panel.textContent=location.hash;'),
            ("collection-context", 'values.filter(v=>v==="ordinary-value","password");'),
            ("unrelated-callback", 'dialog("Title",v=>other==="ordinary-value",true,"password");'),
            ("length-check", 'dialog("Title",v=>v.length===4,true,"password");'),
            ("public-provider-example", 'const example="sk-proj-DocumentationExampleOnly123456789";'),
        ]
        for name, source in negatives:
            self.case(name, source, None, requirement="harmless control; provider example may remain a false alarm")
        self.case("password-help", '<label>Password:</label><a>Forgot password?</a><p>Password: choose at least eight characters</p>', None, kind="text/html", requirement="labels and validation prose")
        self.case("dialog-form", '<form method="dialog"><input type="password" name="password"></form>', None, kind="text/html", requirement="dialog forms do not submit")

        # Each header contract has an explicit oracle; no generic header count
        # contributes to content precision/recall.
        for name, headers, expected in [
            ("weak-csp", {"Content-Security-Policy": "script-src * 'unsafe-inline'"}, "Permissive script CSP"),
            ("wildcard-credentials", {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, "Invalid credentialed wildcard CORS"),
            ("null-origin", {"Access-Control-Allow-Origin": "null"}, "CORS trusts null origin"),
            ("weak-cookie", {"Set-Cookie": "__Host-session=lab; Path=/admin; SameSite=None"}, "Invalid __Host- cookie prefix"),
            ("public-cors-control", {"Access-Control-Allow-Origin": "*"}, None),
            ("secure-control", {}, None),
        ]:
            path = "/headers/" + name
            self.route(path, '<p>Header contract fixture</p>', "text/html", headers)
            self.header_cases.append((path, expected))

        self.route("/blocked/private.js", 'const password="robots-must-not-fetch";')
        self.route("/blocked-redirect", "", "redirect", {"Location": "/blocked/private.js"})
        self.route("/outside-redirect", "", "redirect", {"Location": "https://outside.invalid/must-not-fetch"})
        # Import names and line padding vary reproducibly by seed.
        self.random.shuffle(self.entry_imports)
        self.route("/entry.js", "\n"*self.random.randint(3,40)+''.join('import('+json.dumps(p)+');\n' for p in self.entry_imports))

    def index(self, trap_origin):
        links = self.pages + ["/level/one", "/blocked/private.js", "/blocked-redirect", "/outside-redirect"] + [p for p, _ in self.header_cases]
        return ('<!doctype html><meta charset="utf-8"><title>Gilbrt hard lab</title>'
                '<h1>Gilbrt deliberately vulnerable local laboratory</h1>'
                f'<p>Seed {self.seed}. Synthetic fixtures only. Do not deploy this server.</p>'
                '<script type="module" src="/entry.js"></script><link rel="stylesheet" href="/styles/lab.css">'
                f'<iframe src="{self.frame_path}" title="Nested fixture"></iframe>'
                f'<script src="{trap_origin}/trap.js"></script>'
                + ''.join(f'<p><a href="{html.escape(p)}">{html.escape(p)}</a></p>' for p in links))


HEADERS = {"Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'", "X-Frame-Options": "DENY",
           "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()"}


def make_handler(lab, trap=False):
    class Handler(BaseHTTPRequestHandler):
        server_version = "GilbrtLab"
        sys_version = ""

        def log_message(self, *_):
            pass

        def send(self, status, body=b"", kind="application/json", headers=None):
            self.send_response(status)
            for name, value in {**HEADERS, **(headers or {}), "Content-Type": kind + "; charset=utf-8", "Content-Length": str(len(body))}.items():
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        def do_GET(self):
            path = urlsplit(self.path).path
            with lab.lock:
                lab.visits.append((self.command, path, self.headers.get("Authorization", "")))
                if trap:
                    lab.trap_hits += 1
            if trap:
                return self.send(200, b'const password="cross-origin-must-not-fetch";', "application/javascript")
            if path == "/robots.txt":
                origin = f"http://127.0.0.1:{self.server.server_port}"
                return self.send(200, ("User-agent: *\nDisallow: /blocked/\nSitemap: "+origin+"/pages.xml\n").encode(), "text/plain")
            if path == "/pages.xml":
                origin = f"http://127.0.0.1:{self.server.server_port}"
                return self.send(200, ('<urlset><url><loc>'+origin+lab.sitemap_path+'</loc></url></urlset>').encode(), "application/xml")
            if path == "/":
                return self.send(200, lab.index(self.server.trap_origin).encode(), "text/html")
            if path in {"/records/exposed", "/records/protected"}:
                owner = self.headers.get("Authorization") == "Bearer " + TEST_ENV["GILBRT_LAB_OWNER"]
                if path.endswith("protected") and not owner:
                    return self.send(403, b'{"error":"forbidden"}')
                return self.send(200, json.dumps({"synthetic_record": MARKER}).encode())
            if path == "/contract/good":
                return self.send(200)
            if path == "/contract/bad":
                return self.send(200, headers={"X-Lab-Required": "missing-other-header"})
            if path not in lab.routes:
                return self.send(404)
            body, kind, headers = lab.routes[path]
            return self.send(302 if kind == "redirect" else 200, body, kind, headers)

        do_HEAD = do_GET
        do_OPTIONS = do_GET

        def do_POST(self):
            path = urlsplit(self.path).path
            with lab.lock:
                lab.visits.append(("POST", path, self.headers.get("Authorization", "")))
            if path not in {"/chat/leaky", "/chat/protected"} or self.headers.get("Authorization") != "Bearer " + TEST_ENV["GILBRT_LAB_CHAT"]:
                return self.send(403)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 32768:
                return self.send(400)
            payload = json.loads(self.rfile.read(length))
            marker = re.search(r"GILBRT_[a-f0-9]{32}", payload["messages"][0]["content"]).group()
            answer = marker if path.endswith("leaky") else "The synthetic instruction boundary is enforced."
            return self.send(200, json.dumps({"choices": [{"message": {"content": answer}}]}).encode())
    return Handler


def score_content(cases, findings, visible, metadata, origin):
    inventory = {r["resource"] for r in metadata["resource_inventory"]}
    rows = []
    for case in cases:
        location = safe_url(origin + case.path)
        observed = [f for f in findings if f.url == location and f.category in CONTENT_CATEGORIES]
        reached = location in inventory
        if case.category is None:
            detected = bool(observed)
            outcome = "FP" if detected else "TN" if reached else "UNREACHED_CONTROL"
        else:
            categories = {case.category, "Local AI"} if case.category == "Access code" else {case.category}
            detected = reached and any(f.category in categories and
                           (digest(visible[id(f)]) == case.fingerprint if case.fingerprint else f.title == case.title)
                           for f in observed if not case.fingerprint or id(f) in visible)
            outcome = "TP" if detected else "FN"
        rows.append({"case": case.name, "expected_category": case.category, "outcome": outcome,
                     "reached": reached, "miss_kind": None if detected or case.category is None else "analysis" if reached else "discovery",
                     "requirement": case.requirement, "resource": location,
                     "finding_titles": [f.title for f in observed]})
    counts = {key: sum(r["outcome"] == key for r in rows) for key in ("TP", "FN", "FP", "TN", "UNREACHED_CONTROL")}
    tp, fn, fp = (counts[k] for k in ("TP", "FN", "FP"))
    return {"counts": counts, "precision": tp/(tp+fp) if tp+fp else None,
            "recall": tp/(tp+fn) if tp+fn else None, "cases": rows}


def score_contracts(lab, findings, origin, visits):
    def titles(path, category):
        return [f.title for f in findings if f.url == safe_url(origin + path) and f.category == category]
    paths = {p for _, p, _ in visits}
    headers = []
    for path, expected in lab.header_cases:
        actual = [t for t in titles(path, "Headers") if t != "Missing Strict-Transport-Security"]
        headers.append({"case": path, "expected": expected, "observed": actual,
                        "executed": path in paths,
                        "passed": (expected in actual if expected else not actual) if path in paths else None})
    probes = []
    for path, category, expected, count in [
        ("/records/exposed", "AI isolation", "Synthetic private record exposed", 2),
        ("/records/protected", "AI isolation", "Synthetic marker not observed", 2),
        ("/chat/leaky", "AI prompt", "Synthetic canary disclosed", 1),
        ("/chat/protected", "AI prompt", "Synthetic canary not observed", 1),
        ("/contract/good", "HTTP contract", "HTTP contract satisfied", 1),
        ("/contract/bad", "HTTP contract", "HTTP contract mismatch", 1),
    ]:
        actual = titles(path, category)
        probes.append({"case": path, "expected": expected, "observed": actual,
                       "executed": path in paths,
                       "passed": len(actual) == count and all(t == expected for t in actual) if path in paths else None})
    return {"headers": headers, "configured_active_probes": probes,
            "boundaries": {"robots_blocked_resource_not_requested": "/blocked/private.js" not in paths,
                           "cross_origin_trap_not_requested": lab.trap_hits == 0}}


def active_config():
    return {"environment": "local", "isolation": [
        {"path": "/records/"+mode, "synthetic": True, "marker": MARKER,
         "owner_token_env": "GILBRT_LAB_OWNER", "other_token_env": "GILBRT_LAB_OTHER"} for mode in ("exposed", "protected")],
        "prompts": [{"path": "/chat/"+mode, "model": "synthetic-fixture", "openai_compatible": True,
                     "token_env": "GILBRT_LAB_CHAT"} for mode in ("leaky", "protected")],
        "http_checks": [{"path": "/contract/good", "method": "HEAD", "expected_status": [200], "required_headers": ["X-Content-Type-Options"]},
                        {"path": "/contract/bad", "method": "OPTIONS", "expected_status": [204], "required_headers": ["X-Required-Missing"]}]}


def run_profile(lab, origin, destination, name, *, model=None, limited=False, depth_limited=False, size_limited=False, explicit=False):
    command = ["--url", origin, "--confirm-authorized", "--rate-limit", "0", "--show-secrets",
               "--max-pages", "8" if limited else "128", "--max-depth", "0" if depth_limited else "4",
               "--max-resource-mb", "1" if size_limited else "16",
               "--sitemaps", "--active", "--active-config", str(destination/"active-config.json")]
    if explicit:
        command += ["--include-url", lab.runtime_path]
    if model:
        command += ["--local-model", model, "--ai-max-batches", "0"]
    args = audit_parser().parse_args(command)
    args.hibp_api_key = None
    lab.visits.clear()
    started = time.monotonic()
    selected = CHECKS | ({"local-ai"} if model else set())
    findings, metadata, visible = run_audit(args, selected)
    report = report_document(findings, metadata)
    (destination/(name+".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
    (destination/(name+".html")).write_text(render_report(findings, "html", metadata), encoding="utf-8")
    score = score_content(lab.cases, findings, visible, metadata, origin)
    score["contracts"] = score_contracts(lab, findings, origin, list(lab.visits))
    score["metadata"] = metadata
    score["elapsed_seconds"] = round(time.monotonic()-started, 2)
    score["runtime_api_requested"] = any(p == lab.runtime_path for _,p,_ in lab.visits)
    serialized = json.dumps(report, ensure_ascii=False)
    leaked = [c.name for c in lab.cases if c.fingerprint and any(digest(v) == c.fingerprint and v in serialized for v in visible.values())]
    score["raw_credential_leaks"] = leaked
    score["synthetic_marker_or_token_leak"] = MARKER in serialized or bool(re.search(r"GILBRT_[a-f0-9]{32}", serialized)) or any(v in serialized for v in TEST_ENV.values())
    score["ai_operational"] = None if not model else bool(metadata["local_ai"]["enabled"] and not metadata["local_ai"]["failed"] and not metadata["local_ai"]["budget_reached"])
    print(json.dumps({"profile": name, "counts": score["counts"], "elapsed_seconds": score["elapsed_seconds"], "ai_operational": score["ai_operational"]}), flush=True)
    return score


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261127)
    parser.add_argument("--with-ai", action="store_true", help="Also run the actual installed bundled model")
    parser.add_argument("--model", help="Use an installed Ollama tag instead of bundled (implies --with-ai)")
    parser.add_argument("--serve", action="store_true", help="Leave the lab running for manual GUI audits")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--output-dir", default=".runtime/hard-lab")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    destination = Path(args.output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    lab = Lab(args.seed)
    trap = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(lab, trap=True))
    server = ThreadingHTTPServer(("127.0.0.1", args.port if args.serve else 0), make_handler(lab))
    server.trap_origin = f"http://127.0.0.1:{trap.server_port}"
    origin = f"http://127.0.0.1:{server.server_port}"
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (trap,server)]
    for thread in threads:
        thread.start()
    old_env = {key: os.environ.get(key) for key in TEST_ENV}
    os.environ.update(TEST_ENV)
    try:
        (destination/"manifest.json").write_text(json.dumps({"seed":args.seed,"cases":[asdict(c) for c in lab.cases]},indent=2),encoding="utf-8")
        (destination/"active-config.json").write_text(json.dumps(active_config(),indent=2),encoding="utf-8")
        if args.serve:
            print(f"Local lab: {origin} — {len(lab.cases)} content cases. Ctrl+C stops it.",flush=True)
            print("Ground truth and active config: " + str(destination),flush=True)
            # Event wait is interruptible; this is an explicitly requested server.
            threading.Event().wait()
            return
        results = {"seed": args.seed, "limitations": [
            "Authored local fixtures, not an independent real-world accuracy estimate.",
            "Exact credential fingerprints and resource identity are required; partial strings do not score.",
            "Unreached positive cases count as misses; unreached negative cases never count as true negatives.",
            "Header contracts and configured synthetic API/AI boundary probes are scored separately.",
            "The chat endpoints are deterministic stubs, not actual LLM prompt-injection evaluations.",
            "No SQL injection, server compromise, real provider credential validation, or JS execution is tested."]}
        profiles = [("resource-limited-static", {"limited":True}),
                    ("depth-limited-static", {"depth_limited":True}),
                    ("size-limited-static", {"size_limited":True}),
                    ("full-static", {}), ("explicit-static", {"explicit":True})]
        if args.with_ai or args.model:
            profiles.append(("full-ai", {"model":args.model or "bundled"}))
        for name, options in profiles:
            print(f"Running {name}: {len(lab.cases)} content cases; discovery, header and active contracts separate.",flush=True)
            results[name] = run_profile(lab, origin, destination, name, **options)
            if name == "full-ai":
                baseline = {row["case"]:row["outcome"] for row in results["full-static"]["cases"]}
                results[name]["ai_incremental"] = {
                    "additional_detections": [r["case"] for r in results[name]["cases"] if r["outcome"] == "TP" and baseline[r["case"]] == "FN"],
                    "additional_false_alarms": [r["case"] for r in results[name]["cases"] if r["outcome"] == "FP" and baseline[r["case"]] == "TN"]}
            (destination/"results.json").write_text(json.dumps(results,indent=2),encoding="utf-8")
        print("Results: " + str(destination/"results.json"),flush=True)
        failed = any(not all(r["contracts"]["boundaries"].values()) or r["raw_credential_leaks"] or r["synthetic_marker_or_token_leak"] or r["ai_operational"] is False
                     for r in results.values() if isinstance(r,dict))
        if failed:
            raise SystemExit("Lab integrity, report redaction or model operation failed; inspect results.")
    except KeyboardInterrupt:
        print("Local lab stopped.")
    finally:
        for server_instance in (server,trap):
            server_instance.shutdown()
            server_instance.server_close()
        for thread in threads:
            thread.join()
        for key,value in old_env.items():
            if value is None:
                os.environ.pop(key,None)
            else:
                os.environ[key]=value


if __name__ == "__main__":
    main()
