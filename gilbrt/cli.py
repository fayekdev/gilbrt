"""Argument parsing and authorized audit orchestration."""

import argparse
import math
import os
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.text import Text

from .active import load_config, run_active
from .breach_check import check_breaches
from .crawler import Crawler, ScopedClient, normalize
from .headers import analyze_headers, analyze_tls
from .menu import select_checks
from .local_ai import LocalAnalyzer
from .bundled_ai import BundledAnalyzer, available as bundled_available
from .models import Finding
from .reporter import copy_to_clipboard, export, print_summary, render_report
from .scanner import CONTENT_CHECKS, safe_url, scan
from .updater import update_installation

DEFAULT_CHECKS = ["passwords", "api-keys", "tokens", "private-keys", "entropy", "comments", "endpoints", "headers", "tls", "breaches", "access-codes"]
SEARCH_OPTIONS = DEFAULT_CHECKS + ["local-ai"]


def installed_model_default() -> str:
    """Read the installer-selected local model without treating it as code."""
    path = Path(__file__).resolve().parents[1] / ".runtime" / "default_model.txt"
    try:
        value = path.read_text(encoding="utf-8").strip()
        return value if re.fullmatch(r"[A-Za-z0-9._/-]+(?::[A-Za-z0-9._-]+)?|bundled", value) else "bundled"
    except OSError:
        return "bundled" if bundled_available() else "qwen2.5-coder:0.5b"


def search_selection(value: str) -> set[str]:
    """Parse comma-separated category names or numbered menu selections."""
    selected: set[str] = set()
    for item in value.lower().split(","):
        item = item.strip()
        if item == "all":
            selected.update(DEFAULT_CHECKS)
        elif item.isdigit() and 1 <= int(item) <= len(SEARCH_OPTIONS):
            selected.add(SEARCH_OPTIONS[int(item) - 1])
        elif item in SEARCH_OPTIONS:
            selected.add(item)
        else:
            raise argparse.ArgumentTypeError("Select all or comma-separated search names/numbers shown in --help")
    return selected


def url_argument(value: str) -> str:
    """Reject malformed target URLs without echoing credentials into an error."""
    try:
        return normalize(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Use one http:// or https:// prefix, without credentials, whitespace or backslashes") from None

DISCLAIMER = ("Authorization required: audit only systems you own or have explicit permission to test. "
              "Passive mode uses HTTP GET and a TLS handshake. Active staging probes are opt-in, "
              "may create synthetic chat records and incur model usage charges.")


def nonnegative(value: str) -> float:
    """Parse a finite, nonnegative request delay."""
    try:
        parsed = float(value)
        if not math.isfinite(parsed) or parsed < 0:
            raise ValueError
        return parsed
    except ValueError:
        raise argparse.ArgumentTypeError("must be a finite nonnegative number") from None


def integer(value: str) -> int:
    """Parse a nonnegative integer bound."""
    try:
        parsed = int(value)
        if parsed < 0:
            raise ValueError
        return parsed
    except ValueError:
        raise argparse.ArgumentTypeError("must be a nonnegative integer") from None


def parser() -> argparse.ArgumentParser:
    """Build the public command-line interface."""
    p = argparse.ArgumentParser(prog="gilbrt", description=__doc__)
    p.add_argument("--url", type=url_argument, help="Exact HTTP(S) origin to audit (prompted in interactive mode)")
    p.add_argument("--confirm-authorized", action="store_true",
                   help="Confirm explicit authorization to audit this system")
    p.add_argument("--max-depth", type=integer, default=2)
    p.add_argument("--max-resource-mb", type=integer, default=16,
                   help="Maximum decompressed MiB per fetched resource (1-64; default 16)")
    p.add_argument("--max-pages", type=integer, default=25,
                   help="Maximum total document/JS/source-map attempts (robots and redirects extra)")
    p.add_argument("--rate-limit", type=nonnegative, default=1.0, metavar="SECONDS")
    p.add_argument("--ignore-robots", action="store_true", help="Only for explicitly approved internal environments")
    p.add_argument("--hibp-api-key", default=os.environ.get("HIBP_API_KEY"),
                   help="Optional HIBP catalogue check; prefer HIBP_API_KEY environment variable")
    p.add_argument("--output", help="Report path (may contain sensitive audit metadata)")
    p.add_argument("--copy-report", action="store_true", help="Copy the complete redacted report to the local clipboard")
    p.add_argument("--format", choices=("json", "csv", "html", "ai"), default=None,
                   help="Report format; ai produces Markdown for AI review (default: json in scripts)")
    p.add_argument("--active", action="store_true", help="Enable explicit synthetic staging probes")
    p.add_argument("--active-config", help="JSON staging fixture config; required with --active")
    p.add_argument("--search", type=search_selection, action="append", metavar="CATEGORIES",
                   help="Comma-separated selection (repeatable): all, " + ", ".join(SEARCH_OPTIONS))
    p.add_argument("--interactive", action="store_true", help="Show the guided flow with selectable checkboxes")
    p.add_argument("--update", action="store_true", help="Safely fast-forward and reinstall this Git checkout, then exit")
    p.add_argument("--show-secrets", action="store_true",
                   help="Reveal matched values in the local terminal; exports remain redacted")
    p.add_argument("--include-url", action="append", default=[], metavar="PATH_OR_URL",
                   help="Also fetch this explicit same-origin resource; repeatable, respects robots and limits")
    p.add_argument("--local-model", metavar="TAG", help="Opt in to local analysis: bundled for the small CPU model, or an Ollama tag")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434", help="Local Ollama URL; literal loopback IP only")
    p.add_argument("--ai-max-batches", "--ai-max-chunks", dest="ai_max_chunks", type=integer, default=None, metavar="N",
                   help="Global AI budget: 0 reviews all retained candidates (bundled default); positive values cap calls; Ollama defaults to 12")
    p.add_argument("--ai-candidate-limit", type=integer, default=256,
                   help="Candidates retained per resource for bundled review (24-4096; default 256)")
    return p


def interactive_setup(args: argparse.Namespace, console: Console, selected: set[str]) -> set[str]:
    """Collect website, check selection and report preferences without making requests."""
    console.print("gilbrt — guided website audit", style="bold cyan")
    if not args.url:
        while True:
            try:
                args.url = url_argument(Prompt.ask("Website URL", console=console))
                break
            except argparse.ArgumentTypeError as exc:
                console.print(str(exc), style="yellow")
    if not args.search:
        selected = select_checks(SEARCH_OPTIONS, selected)
        console.print(Text("Selected: " + ", ".join(name for name in SEARCH_OPTIONS if name in selected)))
    if "local-ai" in selected and not args.local_model:
        args.local_model = Prompt.ask("Local model (bundled or an installed Ollama tag)",
                                     default=installed_model_default(), console=console)
    if not args.output and Confirm.ask("Export a full report?", default=True, console=console):
        args.format = Prompt.ask("Report format (ai = Markdown for AI tools)",
                                 choices=["ai", "json", "html", "csv"], default=args.format or "ai", console=console)
        extension = "md" if args.format == "ai" else args.format
        args.output = Prompt.ask("Report file", default=f"gilbrt-report.{extension}", console=console)
    if not args.copy_report:
        args.copy_report = Confirm.ask("Copy the redacted full report to the clipboard?", default=False, console=console)
    if not args.show_secrets:
        args.show_secrets = Confirm.ask("Reveal matched values in this terminal? Exports stay redacted", default=False, console=console)
    if not args.confirm_authorized:
        console.print(DISCLAIMER, style="bold yellow", markup=False)
        args.confirm_authorized = Confirm.ask("Do you own this website or have explicit permission to audit it?", default=False, console=console)
    return selected


def main(argv: list[str] | None = None) -> int:
    """Run an audit; exit 0 completed, 1 configuration/operational error, 130 interrupted."""
    p = parser()
    arguments = sys.argv[1:] if argv is None else argv
    args = p.parse_args(arguments)
    if args.update:
        console = Console()
        try:
            message = update_installation()
            console.print(message, style="green")
            return 0
        except (OSError, ValueError):
            console.print("Update failed. Use a clean Git checkout with network access, or update manually.", style="red")
            return 1
    args.interactive = args.interactive or not arguments
    console = Console()
    selected = set().union(*args.search) if args.search else set(DEFAULT_CHECKS)
    if args.local_model:
        selected.add("local-ai")
    if args.interactive:
        if not sys.stdin.isatty():
            p.error("--interactive needs a terminal; use --url and --search in scripts")
        try:
            selected = interactive_setup(args, console, selected)
        except (KeyboardInterrupt, EOFError):
            console.print("Audit setup cancelled; no requests made.", style="yellow")
            return 130
        if not args.confirm_authorized:
            console.print("Audit cancelled; authorization was not confirmed.", style="yellow")
            return 1
    elif not args.confirm_authorized:
        p.error("--confirm-authorized is required for non-interactive audits")
    if not args.url:
        p.error("--url is required unless --interactive prompts for it")
    if args.max_pages < 1:
        p.error("--max-pages must be at least 1")
    if not 1 <= args.max_resource_mb <= 64:
        p.error("--max-resource-mb must be between 1 and 64")
    if args.ai_max_chunks is not None and not 0 <= args.ai_max_chunks <= 10000:
        p.error("--ai-max-batches/--ai-max-chunks must be between 0 and 10000")
    if not 24 <= args.ai_candidate_limit <= 4096:
        p.error("--ai-candidate-limit must be between 24 and 4096")
    if "local-ai" in selected and not args.local_model:
        p.error("--search local-ai needs --local-model TAG in scripts")
    if args.active != bool(args.active_config):
        p.error("--active and --active-config must be used together")
    args.format = args.format or "json"
    console.print(DISCLAIMER, style="bold yellow", markup=False)
    client = None
    analyzer = None
    try:
        target = normalize(args.url)
        setup_findings = []
        if "local-ai" in selected:
            try:
                budget = args.ai_max_chunks if args.ai_max_chunks is not None else (0 if args.local_model == "bundled" else 12)
                analyzer = (BundledAnalyzer(budget, candidate_limit=args.ai_candidate_limit) if args.local_model == "bundled" else
                            LocalAnalyzer(args.local_model, args.ollama_url, budget))
            except MemoryError:
                setup_findings.append(Finding("Info", "Coverage", "Optional AI skipped: low available memory", safe_url(target),
                                              "The small model needs at least 768 MiB of available physical memory before starting.",
                                              "Close other applications or run static checks; no model process was started."))
        client = ScopedClient(target, args.rate_limit, max_resource_bytes=args.max_resource_mb * 1024 * 1024)
        config = load_config(args.active_config, client) if args.active else None
        crawler = Crawler(client, args.max_depth, args.max_pages, args.ignore_robots, args.include_url)
        visible_values: dict[int, str] = {}
        def reveal(finding: Finding, value: str) -> None:
            """Keep explicit local reveal separate from redacted findings and exports."""
            visible_values[id(finding)] = value
        findings = setup_findings
        resources = 0
        resource_inventory = []
        with console.status("Auditing authorized scope…") as status:
            if analyzer and args.local_model == "bundled":
                analyzer.progress = lambda batch, remaining: status.update(f"AI review batch {batch}; {remaining} candidates pending in this resource…")
            # Respect the same pacing clock for TLS, crawl, HIBP and active probes.
            if "tls" in selected:
                client.pace()
                findings.extend(analyze_tls(target))
            for resource in crawler.crawl():
                resources += 1
                resource_inventory.append({"resource": safe_url(resource.url), "status": resource.response.status_code,
                                           "kind": "HTML" if resource.html else "Client-side content",
                                           "bytes": len(resource.response.content)})
                if resource.html and "headers" in selected:
                    findings.extend(analyze_headers(resource.response))
                findings.extend(scan(resource.body, resource.url, resource.html, selected & CONTENT_CHECKS,
                                     reveal if args.show_secrets else None))
                if analyzer:
                    findings.extend(analyzer.analyze(resource.body, resource.url, resource.html,
                                                     reveal if args.show_secrets else None))
                if resource.response.status_code >= 400:
                    client.issue("HTTP error response audited", resource.url)
            if args.hibp_api_key and "breaches" in selected:
                client.pace()
                findings.extend(check_breaches(target, args.hibp_api_key))
            if config:
                findings.extend(run_active(client, config, crawler.permitted))
            if analyzer and analyzer.skipped:
                unit = "candidate batches" if args.local_model == "bundled" else "source chunks"
                findings.append(Finding("Info", "Coverage", "Local AI review budget reached", safe_url(target),
                                        f"Analyzed {analyzer.completed} {unit}; remaining candidates/source were not model-reviewed.",
                                        "Use --ai-max-batches 0 to review all retained candidates sequentially."))
            if analyzer and getattr(analyzer, "candidate_limit_reached", False):
                findings.append(Finding("Info", "Coverage", "Candidate queue limit reached", safe_url(target),
                                        f"More than {args.ai_candidate_limit} candidates were found in a resource; highest-ranked candidates were reviewed.",
                                        "Raise --ai-candidate-limit to retain more candidates; inference remains sequential."))
            findings.extend(client.errors)
        print_summary(findings, console, visible_values if args.show_secrets else None)
        if resources == 0:
            console.print("No source resources were scanned. This run cannot establish whether passwords or codes are exposed.", style="bold yellow")
        console.print(f"Scanned {resources} resources; {len(findings)} observations. Coverage is bounded.")
        metadata = {"target": safe_url(target), "resources_scanned": resources, "active": args.active,
                    "robots_respected": not args.ignore_robots, "max_depth": args.max_depth,
                    "max_pages": args.max_pages, "rate_limit_seconds": args.rate_limit,
                    "search_categories": sorted(selected), "resource_inventory": resource_inventory,
                    "hibp_queried": bool(args.hibp_api_key and "breaches" in selected),
                    "max_resource_mb": args.max_resource_mb,
                    "local_ai": {"requested": "local-ai" in selected, "enabled": analyzer is not None,
                                 "chunks_analyzed": analyzer.completed if analyzer else 0,
                                 "chunks_submitted": analyzer.used if analyzer else 0,
                                 "budget_reached": analyzer.skipped if analyzer else False,
                                 "failed": analyzer.failed if analyzer else False,
                                 "backend": ("llama.cpp" if args.local_model == "bundled" else "ollama") if analyzer else None,
                                 "context_tokens": analyzer.context_size if analyzer else None,
                                 "budget_unit": "candidate_batches" if analyzer and args.local_model == "bundled" else "source_chunks" if analyzer else None,
                                 "chunk_characters": analyzer.chunk_size if analyzer and args.local_model != "bundled" else None,
                                 "candidate_excerpt_characters": 280 if analyzer and args.local_model == "bundled" else None,
                                 "relevant_candidates": getattr(analyzer, "relevant_candidates", None) if analyzer else None,
                                 "reviewed_candidates": getattr(analyzer, "reviewed_candidates", None) if analyzer else None,
                                 "cached_candidate_reviews": getattr(analyzer, "cache_hits", None) if analyzer else None,
                                 "candidate_limit": args.ai_candidate_limit if analyzer and args.local_model == "bundled" else None,
                                 "candidate_limit_reached": getattr(analyzer, "candidate_limit_reached", False) if analyzer else False,
                                 "runner_peak_rss_bytes": analyzer.memory_bytes() if analyzer and args.local_model == "bundled" else None}}
        if args.output:
            export(findings, args.output, args.format, metadata)
            console.print(Text(f"Full report written: {os.path.abspath(args.output)}", style="green"))
        if args.copy_report:
            try:
                copy_to_clipboard(render_report(findings, args.format, metadata))
                console.print("Redacted full report copied to the clipboard.", style="green")
            except OSError:
                console.print("Clipboard unavailable. Install wl-clipboard/xclip on Linux, or use --output.", style="yellow")
        return 0
    except KeyboardInterrupt:
        console.print("Audit interrupted; no partial report written.", style="yellow")
        return 130
    except (ValueError, OSError):
        console.print("Audit failed: invalid configuration or report path. Details withheld to protect credentials.", style="red")
        return 1
    finally:
        if client:
            client.session.close()
        if analyzer:
            analyzer.close()
