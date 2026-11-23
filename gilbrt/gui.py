"""Loopback-bound GUI with exact local and Codespaces origin validation."""

import copy
import json
import math
import os
import re
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests

from .bundled_ai import RUNTIME, available as bundled_available, available_memory_bytes
from .cli import AuditCancelled, DEFAULT_CHECKS, SEARCH_OPTIONS, parser, run_audit
from .crawler import ScopedClient, normalize
from .local_ai import loopback_url
from .model_install import MODELS
from .reporter import render_report

ASSETS = Path(__file__).with_name("gui_assets")
DEFAULT_SETTINGS = {
    "max_pages": 25, "max_depth": 2, "max_resource_mb": 16, "rate_limit": 1.0,
    "ignore_robots": False, "checks": DEFAULT_CHECKS, "model": "",
    "ollama_url": "http://127.0.0.1:11434", "ai_max_chunks": None,
    "ai_candidate_limit": 256, "export_format": "json",
}


class APIError(Exception):
    """An intentionally safe error to display in the local interface."""

    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def validate_settings(data):
    """Validate all settings before saving or using them; never accept CLI flags."""
    if not isinstance(data, dict) or set(data) - DEFAULT_SETTINGS.keys():
        raise APIError("Unknown settings or invalid settings object.")
    result = {**copy.deepcopy(DEFAULT_SETTINGS), **data}
    for key, low, high in (("max_pages", 1, 10000), ("max_depth", 0, 20),
                           ("max_resource_mb", 1, 64), ("ai_candidate_limit", 24, 4096)):
        value = result[key]
        if type(value) is not int or not low <= value <= high:
            raise APIError(f"{key} must be an integer between {low} and {high}.")
    budget = result["ai_max_chunks"]
    if budget is not None and (type(budget) is not int or not 0 <= budget <= 10000):
        raise APIError("AI budget must be empty (backend default), or 0–10000.")
    delay = result["rate_limit"]
    if type(delay) not in (int, float) or not math.isfinite(delay) or not 0 <= delay <= 3600:
        raise APIError("Request delay must be a finite number between 0 and 3600 seconds.")
    if type(result["ignore_robots"]) is not bool:
        raise APIError("Robots preference must be true or false.")
    checks = result["checks"]
    if not isinstance(checks, list) or not checks or any(not isinstance(x, str) or x not in DEFAULT_CHECKS for x in checks):
        raise APIError("Select at least one valid static audit check.")
    result["checks"] = list(dict.fromkeys(checks))
    model = result["model"]
    if not isinstance(model, str) or (model and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}", model)) or "cloud" in model.lower():
        raise APIError("Choose an installed local model, or static checks only.")
    try:
        result["ollama_url"] = loopback_url(result["ollama_url"])
    except (ValueError, TypeError, AttributeError):
        raise APIError("Ollama URL must use an HTTP loopback IP, such as http://127.0.0.1:11434.") from None
    if result["export_format"] not in {"json", "csv", "html", "ai"}:
        raise APIError("Choose JSON, CSV, HTML, or AI Markdown export.")
    return result


def discover_models(base_url):
    """Discover installed models; never download weights or follow redirects."""
    choices = [{"id": "", "name": "Static checks only", "backend": "No model"}]
    if bundled_available():
        choices.append({"id": "bundled", "name": "Qwen2.5-Coder 0.5B · bundled CPU", "backend": "llama.cpp"})
    status = "Ollama is unavailable at this address."
    try:
        with requests.Session() as session:
            session.trust_env = False
            with session.get(loopback_url(base_url) + "/api/tags", timeout=(1, 2), stream=True, allow_redirects=False) as response:
                if response.status_code != 200:
                    raise ValueError()
                body = bytearray()
                for chunk in response.iter_content(16384):
                    body.extend(chunk)
                    if len(body) > 1024 * 1024:
                        raise ValueError()
                models = json.loads(body).get("models")
                if not isinstance(models, list):
                    raise ValueError()
                for model in models[:256]:
                    if not isinstance(model, dict):
                        continue
                    name = model.get("name")
                    size = model.get("size")
                    if (isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,160}", name)
                            and "cloud" not in name.lower() and not model.get("remote_host")
                            and not model.get("remote_model") and type(size) is int and size > 0 and name != "bundled"):
                        choices.append({"id": name, "name": name, "backend": "Ollama", "bytes": size})
                status = "Ollama connected. Only installed local models are listed."
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        pass
    memory = available_memory_bytes()
    return {"choices": choices, "status": status, "available_memory_bytes": memory,
            "catalogue": [{"id": model.key, "download": model.download, "ram_gib": model.ram_gib} for model in MODELS]}


class GUIState:
    """One local audit at a time; reports and targets are never persisted."""

    def __init__(self, settings_path=None):
        self.settings_path = settings_path or RUNTIME / "gui-settings.json"
        self.lock = threading.RLock()
        self.token = secrets.token_urlsafe(32)
        self.settings = copy.deepcopy(DEFAULT_SETTINGS)
        try:
            self.settings = validate_settings(json.loads(self.settings_path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, APIError):
            pass
        self.cancel = threading.Event()
        self.job = None
        self.report = None
        self.thread = None

    def save_settings(self, data):
        settings = validate_settings(data)
        with self.lock:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.settings_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(settings, indent=2), encoding="utf-8")
            temporary.replace(self.settings_path)
            self.settings = settings
        return settings

    def snapshot(self):
        with self.lock:
            return copy.deepcopy({"job": self.job, "report": self.report})

    def start(self, data):
        if not isinstance(data, dict) or data.get("authorized") is not True:
            raise APIError("Confirm that you own the target or have explicit permission to audit it.")
        try:
            target = normalize(data.get("target", ""))
        except (ValueError, TypeError, AttributeError):
            raise APIError("Enter a valid HTTP(S) target without embedded credentials.") from None
        settings = validate_settings(data.get("settings", self.settings))
        includes = data.get("include_urls", [])
        if not isinstance(includes, list) or len(includes) > 100 or any(not isinstance(x, str) or len(x) > 4096 for x in includes):
            raise APIError("Use at most 100 additional same-origin resource URLs.")
        from urllib.parse import urljoin
        scope = ScopedClient(target)
        try:
            if any(not scope.allowed(urljoin(target, item)) for item in includes):
                raise APIError("Additional resource URLs must match the target's exact origin.")
        finally:
            scope.session.close()
        with self.lock:
            if self.job and self.job["status"] in {"running", "cancelling"}:
                raise APIError("An audit is already running. Finish or cancel it first.", 409)
            # Model discovery is bounded and stays under the start lock to avoid overlapping launches.
            if settings["model"] and settings["model"] not in {m["id"] for m in discover_models(settings["ollama_url"])["choices"]}:
                raise APIError("The selected local model is not installed or reachable. Refresh models in Settings.")
            self.cancel.clear()
            self.job = {"id": secrets.token_hex(8), "status": "running", "target": target,
                        "started_at": time.time(), "elapsed": 0, "events": [], "stage": "Preparing audit",
                        "resources_scanned": 0, "findings": 0}
            self.thread = threading.Thread(target=self._run, args=(target, settings, includes), daemon=True)
            self.thread.start()
            return copy.deepcopy(self.job)

    def _run(self, target, settings, includes):
        try:
            args = parser().parse_args([])
            for name, value in settings.items():
                if hasattr(args, name):
                    setattr(args, name, value)
            args.url = target
            args.confirm_authorized = True
            args.local_model = settings["model"] or None
            args.include_url = includes
            selected = set(settings["checks"])
            if args.local_model:
                selected.add("local-ai")

            def progress(event):
                with self.lock:
                    self.job.update({key: value for key, value in event.items() if key in {"stage", "resources_scanned", "findings"}})
                    self.job["elapsed"] = round(time.time() - self.job["started_at"], 1)
                    self.job["events"].append({**event, "elapsed": self.job["elapsed"]})
                    self.job["events"] = self.job["events"][-60:]

            findings, metadata, _ = run_audit(args, selected, progress, self.cancel.is_set)
            with self.lock:
                if self.cancel.is_set():
                    raise AuditCancelled()
                self.report = json.loads(render_report(findings, "json", metadata))
                self.report["session"] = {"target_origin": f"{urlsplit(target).scheme}://{urlsplit(target).netloc}",
                                          "elapsed": round(time.time() - self.job["started_at"], 1)}
                self.job.update(status="complete", stage="Audit complete", elapsed=self.report["session"]["elapsed"])
        except AuditCancelled:
            with self.lock:
                self.job.update(status="cancelled", stage="Audit cancelled", elapsed=round(time.time() - self.job["started_at"], 1))
        except Exception:
            # Never return exception messages or source text to the browser or logs.
            with self.lock:
                self.job.update(status="failed", stage="Audit failed",
                                error="Audit failed. Check scope, selected model availability, and tool configuration.",
                                elapsed=round(time.time() - self.job["started_at"], 1))

    def cancel_audit(self):
        with self.lock:
            if self.job and self.job["status"] == "running":
                self.cancel.set()
                self.job.update(status="cancelling", stage="Stopping after the current network or inference call")


def codespaces_origin(port):
    """Derive one exact forwarded origin from GitHub's Codespaces environment.

    Never trust request-supplied forwarding headers or a wildcard domain. Private
    forwarded-port access is authenticated by Codespaces, outside this server.
    """
    if os.environ.get("CODESPACES") != "true":
        return None
    name = os.environ.get("CODESPACE_NAME", "")
    domain = os.environ.get("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN", "")
    host = f"{name}-{port}.{domain}"
    label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if (not name or not domain or "." not in domain or len(host) > 253
            or not re.fullmatch(label, name)
            or any(not re.fullmatch(label, item) for item in host.split("."))):
        return None
    return f"https://{host}"


class GUIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=4174, state=None):
        self.state = state or GUIState()
        super().__init__(("127.0.0.1", port), GUIHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.local_origins = {self.origin, f"http://localhost:{self.server_port}"}
        self.forwarded_origin = codespaces_origin(self.server_port)
        self.allowed_origins = set(self.local_origins)
        if self.forwarded_origin:
            self.allowed_origins.add(self.forwarded_origin)


class GUIHandler(BaseHTTPRequestHandler):
    """Serve an asset allowlist and same-origin, token-protected JSON API."""

    def log_message(self, *_args):
        pass

    def _guard(self, token=True):
        host = self.headers.get("Host")
        allowed_hosts = {urlsplit(origin).netloc for origin in self.server.allowed_origins}
        if len(self.headers.get_all("Host", [])) != 1 or host not in allowed_hosts:
            raise APIError("Invalid local host.", 403)
        # Opening the UI from a Codespaces link is a safe document navigation.
        # Cross-site API fetches, including bootstrap, are still denied.
        document_navigation = (self.command == "GET" and urlsplit(self.path).path in {"/", "/index.html"}
                               and self.headers.get("Sec-Fetch-Mode") == "navigate")
        if self.headers.get("Sec-Fetch-Site") == "cross-site" and not document_navigation:
            raise APIError("Cross-site requests are not allowed.", 403)
        origin = self.headers.get("Origin")
        # Some proxies preserve Host, others rewrite it to the loopback upstream.
        # Both cases require the exact known origin; no forwarding headers are trusted.
        expected_origins = (self.server.allowed_origins if host in {urlsplit(item).netloc for item in self.server.local_origins}
                            else {self.server.forwarded_origin})
        if origin and origin not in expected_origins:
            raise APIError("Invalid local origin.", 403)
        if token and not secrets.compare_digest(self.headers.get("X-Gilbrt-Token", ""), self.server.state.token):
            raise APIError("Reload the GUI to restore the local session.", 403)

    def _send(self, body, status=200, content_type="application/json; charset=utf-8", filename=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode() if content_type.startswith("application/json") else body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            self._guard(token=path.startswith("/api/") and path != "/api/bootstrap")
            state = self.server.state
            if path == "/api/bootstrap":
                return self._send({"token": state.token, "settings": state.settings, "checks": DEFAULT_CHECKS,
                                   "hibp_available": bool(os.environ.get("HIBP_API_KEY")), **state.snapshot()})
            if path == "/api/state":
                return self._send(state.snapshot())
            if path == "/api/models":
                address = parse_qs(urlsplit(self.path).query).get("url", [state.settings["ollama_url"]])[0]
                try:
                    address = loopback_url(address)
                except (ValueError, TypeError):
                    raise APIError("Use a valid loopback Ollama URL.") from None
                return self._send(discover_models(address))
            if path == "/api/export":
                report = state.snapshot()["report"]
                if not report:
                    raise APIError("Complete an audit before exporting a report.", 409)
                fmt = parse_qs(urlsplit(self.path).query).get("format", ["json"])[0]
                types = {"json": "application/json", "html": "text/html", "csv": "text/csv", "ai": "text/markdown"}
                if fmt not in types:
                    raise APIError("Unsupported report format.")
                from .models import Finding
                findings = [Finding(**item) for item in report["findings"]]
                rendered = render_report(findings, fmt, report["metadata"])
                if fmt == "csv":
                    rendered = "\ufeff" + rendered
                return self._send(rendered.encode("utf-8"), content_type=types[fmt]+"; charset=utf-8",
                                  filename="gilbrt-report." + ("md" if fmt == "ai" else fmt))
            assets = {"/": ("index.html", "text/html"), "/index.html": ("index.html", "text/html"),
                      "/app.js": ("app.js", "text/javascript"), "/style.css": ("style.css", "text/css"),
                      "/mascot.svg": ("mascot.svg", "image/svg+xml")}
            if path not in assets:
                raise APIError("Not found.", 404)
            name, kind = assets[path]
            return self._send((ASSETS / name).read_bytes(), content_type=kind+"; charset=utf-8")
        except APIError as error:
            self._send({"error": str(error)}, error.status)
        except (OSError, ValueError):
            self._send({"error": "Unable to read local interface data."}, 500)

    def do_POST(self):
        try:
            self._guard()
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                raise APIError("JSON requests are required.", 415)
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536:
                raise APIError("Request body must be between 1 and 65536 bytes.")
            data = json.loads(self.rfile.read(length))
            path = urlsplit(self.path).path
            state = self.server.state
            if path == "/api/settings":
                return self._send({"settings": state.save_settings(data)})
            if path == "/api/audit":
                return self._send({"job": state.start(data)}, 202)
            if path == "/api/cancel":
                state.cancel_audit()
                return self._send(state.snapshot())
            raise APIError("Not found.", 404)
        except APIError as error:
            self._send({"error": str(error)}, error.status)
        except (ValueError, TypeError, OSError):
            self._send({"error": "Invalid request or settings could not be saved."}, 400)


def serve(port=4174, open_browser=True):
    if not 1 <= port <= 65535:
        print("GUI port must be between 1 and 65535.")
        return 1
    try:
        server = GUIServer(port)
    except OSError:
        print("GUI port is unavailable. Choose another with --gui-port.")
        return 1
    print(f"gilbrt GUI: {server.origin} (local only; Ctrl+C to stop)", flush=True)
    if server.forwarded_origin:
        print(f"Codespaces GUI: {server.forwarded_origin} (keep port visibility Private)", flush=True)
    if open_browser and os.environ.get("CODESPACES") != "true":
        webbrowser.open(server.origin)
    try:
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.state.cancel_audit()
        server.server_close()
        if server.state.thread:
            if server.state.thread.is_alive():
                print("Stopping after the current request; waiting for model cleanup…", flush=True)
            server.state.thread.join()
    return 0
