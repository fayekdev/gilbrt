"""Inspect selected text files without crawling, DNS, or remote services."""

import hashlib
from pathlib import PurePosixPath

from .bundled_ai import BundledAnalyzer
from .cli import AuditCancelled
from .local_ai import LocalAnalyzer
from .models import Finding
from .scanner import CONTENT_CHECKS, safe_url, scan

MAX_UPLOAD_BYTES = 16 * 1024 * 1024
MAX_FILES = 100
EXTENSIONS = {".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map", ".txt", ".css"}


def validate_files(files):
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Choose between 1 and 100 source files.")
    total = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {"name", "content"}:
            raise ValueError("Each source file needs a name and text content.")
        name, content = item["name"], item["content"]
        if (not isinstance(name, str) or not 1 <= len(name) <= 512
                or PurePosixPath(name.replace("\\", "/")).suffix.lower() not in EXTENSIONS
                or not isinstance(content, str) or "\x00" in content):
            raise ValueError("Choose supported text source files (HTML, JavaScript, TypeScript, JSON, maps, CSS or TXT).")
        total += len(content.encode("utf-8"))
        if total > MAX_UPLOAD_BYTES:
            raise ValueError("Selected files exceed the combined 16 MiB limit.")
    return files


def run_local_audit(args, selected, files, progress=None, cancelled=None):
    """Use the regular detectors and optional installed local model on file text.

    Filenames become redacted resource digests. Original source is never persisted.
    Website-only checks are omitted and recorded separately in report metadata.
    """
    def emit(stage, **details):
        if cancelled and cancelled():
            raise AuditCancelled()
        if progress:
            progress({"stage": stage, **details})

    emit("Reading local files")
    files = validate_files(files)
    enabled = selected & CONTENT_CHECKS
    findings, inventory, visible = [], [], {}
    analyzer = None
    try:
        if "local-ai" in selected:
            budget = args.ai_max_chunks if args.ai_max_chunks is not None else (0 if args.local_model == "bundled" else 12)
            try:
                analyzer = (BundledAnalyzer(budget, candidate_limit=args.ai_candidate_limit)
                            if args.local_model == "bundled" else LocalAnalyzer(args.local_model, args.ollama_url, budget))
            except MemoryError:
                findings.append(Finding("Info", "Coverage", "Local model skipped: low memory", "file://local/",
                                        "Not enough available memory to start the installed model.",
                                        "Free memory or use static checks."))
        if analyzer:
            request = analyzer.request
            def checked_request(*args, **kwargs):
                emit("Local model review")
                result = request(*args, **kwargs)
                emit("Local model review")
                return result
            analyzer.request = checked_request
            if args.local_model == "bundled":
                analyzer.progress = lambda batch, remaining: emit("Local model review", batch=batch, candidates_pending=remaining)
        for index, item in enumerate(files[:args.max_pages]):
            emit("Scanning local file", resources_scanned=len(inventory), findings=len(findings))
            identity = hashlib.sha256(f"{index}:{item['name']}".encode()).hexdigest()[:12]
            url = f"file://local/{identity}"
            size = len(item["content"].encode("utf-8"))
            if size > args.max_resource_mb * 1024 * 1024:
                findings.append(Finding("Info", "Coverage", "Local file exceeds size limit", safe_url(url),
                                        "File was not scanned.", "Increase the per-resource limit in Settings."))
                continue
            suffix = PurePosixPath(item["name"].replace("\\", "/")).suffix.lower()
            html = suffix in {".html", ".htm"}
            remembered = {}
            def remember(finding, value):
                remembered[id(finding)] = hashlib.sha256(value.encode()).digest()
                if args.show_secrets:
                    visible[id(finding)] = value
            static = scan(item["content"], url, html, enabled, remember)
            findings.extend(static)
            if analyzer:
                seen = {remembered[id(f)] for f in static if f.category in {"Password", "Access code"} and id(f) in remembered}
                for finding in analyzer.analyze(item["content"], url, html, remember):
                    if finding.category in {"Password", "Local AI"} and remembered.get(id(finding)) in seen:
                        visible.pop(id(finding), None)
                    else:
                        findings.append(finding)
            inventory.append({"resource": safe_url(url), "kind": "HTML" if html else "Source",
                              "bytes": size, "status": None})
            emit("File scanned", resource=safe_url(url), resources_scanned=len(inventory), findings=len(findings))
        if len(files) > args.max_pages:
            findings.append(Finding("Info", "Coverage", "Local file limit reached", "file://local/",
                                    f"Inspected at most {args.max_pages} of {len(files)} selected files.",
                                    "Increase the resource limit or select fewer files."))
        if analyzer and (analyzer.skipped or getattr(analyzer, "candidate_limit_reached", False)):
            findings.append(Finding("Info", "Coverage", "Local model review limited", "file://local/",
                                    "The model budget or candidate limit was reached.", "Adjust model limits in Settings."))
        metadata = {"target": "file://local/", "mode": "files", "resources_scanned": len(inventory),
                    "resources_attempted": min(len(files), args.max_pages), "files_selected": len(files),
                    "active": False, "max_pages": args.max_pages, "max_resource_mb": args.max_resource_mb,
                    "resource_inventory": inventory, "search_categories": sorted(enabled | (selected & {"local-ai"})),
                    "unavailable_checks": sorted(selected - CONTENT_CHECKS - {"local-ai"}), "hibp_queried": False,
                    "local_ai": {"requested": "local-ai" in selected, "enabled": analyzer is not None,
                                 "backend": ("llama.cpp" if args.local_model == "bundled" else "ollama") if analyzer else None,
                                 "chunks_analyzed": analyzer.completed if analyzer else 0,
                                 "failed": analyzer.failed if analyzer else False,
                                 "budget_reached": analyzer.skipped if analyzer else False}}
        emit("Complete", resources_scanned=len(inventory), findings=len(findings))
        return findings, metadata, visible
    finally:
        if analyzer:
            analyzer.close()
