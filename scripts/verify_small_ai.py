"""Run synthetic native-model checks and record observed memory/timing locally."""

import json
import os
import time
from pathlib import Path

from gilbrt.bundled_ai import BundledAnalyzer, peak_memory_bytes


def main() -> None:
    """Verify inference transport, detection on one example and runner shutdown."""
    started = time.monotonic()
    analyzer = BundledAnalyzer(max_chunks=2)
    load_seconds = time.monotonic() - started
    process = analyzer.process
    try:
        started = time.monotonic()
        positive = analyzer.analyze('function login(v) { if (v === "gilbrt-test-4827") { return true; } return false; }',
                                    "https://synthetic.invalid/positive.js")
        negative = analyzer.analyze('const heading = "Welcome"; console.log(heading);',
                                    "https://synthetic.invalid/negative.js")
        report = {"model": "Qwen2.5-Coder-0.5B-Instruct Q4_K_M", "synthetic_only": True,
                  "threads": 1, "context_tokens": analyzer.context_size, "max_output_tokens": analyzer.output_tokens,
                  "load_seconds": round(load_seconds, 2), "inference_seconds": round(time.monotonic() - started, 2),
                  "chunks_completed": analyzer.completed, "failed": analyzer.failed,
                  "positive_candidates": sum(f.category == "Local AI" for f in positive),
                  "negative_candidates": sum(f.category == "Local AI" for f in negative),
                  "runner_peak_rss_bytes": analyzer.memory_bytes(), "python_peak_rss_bytes": peak_memory_bytes(os.getpid()),
                  "limitations": "Measured on the current host; not a guarantee for sub-2-GB machines or a detection accuracy benchmark."}
    finally:
        analyzer.close()
    report["owned_runner_stopped"] = process.poll() is not None
    destination = Path(__file__).resolve().parents[1] / ".runtime" / "verification.json"
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
