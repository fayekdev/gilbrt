"""Native-runner lifecycle checks without loading model weights in the unit suite."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from gilbrt.bundled_ai import BundledAnalyzer
from gilbrt.local_ai import chunks


class BundledTests(unittest.TestCase):
    """Validate constrained launch settings, source grounding and owned process cleanup."""

    def stub_analyzer(self, budget: int = 0, limit: int = 256) -> BundledAnalyzer:
        """Build a scheduler with deterministic local responses and no model process."""
        analyzer = object.__new__(BundledAnalyzer)
        analyzer.failed = analyzer.fatal = analyzer.skipped = analyzer.candidate_limit_reached = False
        analyzer.seen = set()
        analyzer.used = analyzer.completed = analyzer.relevant_candidates = analyzer.reviewed_candidates = analyzer.cache_hits = 0
        analyzer.max_chunks, analyzer.candidate_limit = budget, limit
        analyzer.review_cache = {}
        analyzer.progress = None
        analyzer.verify_model = MagicMock()
        def choose_all(_path, payload):
            ids = [item["id"] for item in json.loads(payload["prompt"])]
            return {"done": True, "response": json.dumps({"candidate_ids": ids})}
        analyzer.request = MagicMock(side_effect=choose_all)
        return analyzer

    def test_default_reviews_more_than_old_limits_and_reuses_cross_page_cache(self) -> None:
        analyzer = self.stub_analyzer()
        source = ';'.join(f'if(code == "fixture-code-{index}")allow()' for index in range(40))
        first = analyzer.analyze(source, "https://test.invalid/one.js")
        self.assertEqual(len(first), 40)
        self.assertEqual(analyzer.reviewed_candidates, 40)
        self.assertGreater(analyzer.used, 2)
        self.assertFalse(analyzer.skipped)
        calls = analyzer.used
        second = analyzer.analyze(source, "https://test.invalid/two.js")
        self.assertEqual(len(second), 40)
        self.assertEqual(analyzer.cache_hits, 40)
        self.assertEqual(analyzer.used, calls)

    def test_queue_is_bounded_and_reports_real_limit(self) -> None:
        analyzer = self.stub_analyzer(limit=24)
        source = ';'.join(f'if(code == "fixture-code-{index}")allow()' for index in range(40))
        analyzer.analyze(source, "https://test.invalid/main.js")
        self.assertTrue(analyzer.candidate_limit_reached)
        self.assertEqual(analyzer.reviewed_candidates, 24)

    def test_reviewed_password_is_critical_and_reveal_targets_its_row(self) -> None:
        analyzer = self.stub_analyzer()
        visible = {}
        findings = analyzer.analyze('if(password == "fixture-password")allow();', "https://test.invalid/main.js",
                                    on_secret=lambda finding, value: visible.__setitem__(id(finding), value))
        self.assertEqual(findings[0].severity, "Critical")
        self.assertEqual(findings[0].category, "Password")
        self.assertEqual(visible[id(findings[0])], "fixture-password")
        self.assertNotIn("fixture-password", str(findings))

    def test_small_runner_settings_and_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.exe").write_bytes(b"test")
            (root / "model.gguf").write_bytes(b"GGUF")
            (root / "manifest.json").write_text(json.dumps({"server": "server.exe", "model": "model.gguf", "model_bytes": 4}))
            process = MagicMock()
            process.pid = 12345
            state = {"ended": False}
            process.poll.side_effect = lambda: 0 if state["ended"] else None
            process.terminate.side_effect = lambda: state.update(ended=True)
            session = MagicMock()
            session.headers = {}
            session.get.return_value.__enter__.return_value.status_code = 200
            response = session.post.return_value.__enter__.return_value
            response.status_code = 200
            response.iter_content.return_value = [json.dumps({"choices": [{"finish_reason": "stop", "message": {
                "content": json.dumps({"candidate_ids": [0]})}}]}).encode()]
            with patch("gilbrt.bundled_ai.RUNTIME", root), patch("gilbrt.bundled_ai.subprocess.Popen", return_value=process) as popen, \
                 patch("gilbrt.local_ai.requests.Session", return_value=session), \
                 patch("gilbrt.bundled_ai.peak_memory_bytes", return_value=123456):
                analyzer = BundledAnalyzer()
                try:
                    html = ('<script type="application/json">{"build":"dev"}</script>'
                            '<script>const assets="' + 'A' * 20000 + 'auth' + 'A' * 20000 + '";</script>'
                            '<script>if(x === "synthetic-code")allow();</script>')
                    findings = analyzer.analyze(html, "https://synthetic.invalid/", html=True)
                    self.assertEqual(len(findings), 1)
                    self.assertNotIn("synthetic-code", str(findings))
                    args = popen.call_args.args[0]
                    for flag, value in (("--threads", "1"), ("--threads-batch", "1"), ("--ctx-size", "2048"),
                                        ("--parallel", "1"), ("--batch-size", "32"), ("--n-gpu-layers", "0")):
                        self.assertEqual(args[args.index(flag) + 1], value)
                    self.assertEqual(session.post.call_args.kwargs["json"]["max_tokens"], 64)
                    prompt = session.post.call_args.kwargs["json"]["messages"][1]["content"]
                    self.assertIn("synthetic-code", prompt)
                    self.assertNotIn("assets", prompt)
                    self.assertNotIn('"build"', prompt)
                    self.assertEqual(analyzer.used, 1)
                    self.assertEqual(analyzer.max_chunks, 0)
                finally:
                    analyzer.close()
                process.terminate.assert_called_once()
                process.wait.assert_called_once()
                session.close.assert_called_once()

    def test_manifest_cannot_launch_outside_runtime_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manifest.json").write_text(json.dumps({"server": "../outside.exe", "model": "model.gguf"}))
            with patch("gilbrt.bundled_ai.RUNTIME", root), patch("gilbrt.bundled_ai.subprocess.Popen") as popen:
                with self.assertRaises(ValueError):
                    BundledAnalyzer()
                popen.assert_not_called()

    def test_prioritized_keyword_is_inside_short_window(self) -> None:
        for size, offset in ((700, 1500), (4000, 4500)):
            with self.subTest(size=size):
                source = "A" * offset + ' const adminCode="synthetic-code";'
                first, _ = next(chunks(source, size=size))
                self.assertIn("adminCode", first)

    def test_low_memory_skips_process_creation(self) -> None:
        with patch("gilbrt.bundled_ai.available_memory_bytes", return_value=128 * 1024 * 1024), \
             patch("gilbrt.bundled_ai.subprocess.Popen") as popen:
            with self.assertRaises(MemoryError):
                BundledAnalyzer()
            popen.assert_not_called()

    def test_truncated_batch_does_not_prevent_next_bounded_batch(self) -> None:
        analyzer = object.__new__(BundledAnalyzer)
        analyzer.failed = False
        analyzer.seen = set()
        analyzer.used = analyzer.completed = 0
        analyzer.max_chunks = 2
        analyzer.skipped = False
        analyzer.fatal = False
        analyzer.candidate_limit = 256
        analyzer.candidate_limit_reached = False
        analyzer.relevant_candidates = analyzer.reviewed_candidates = analyzer.cache_hits = 0
        analyzer.review_cache = {}
        analyzer.progress = None
        analyzer.verify_model = MagicMock()
        analyzer.request = MagicMock(side_effect=[
            {"done": False, "stop_reason": "length", "response": '{"candidate_ids":['},
            {"done": True, "response": '{"candidate_ids":[0]}'},
        ])
        source = ';'.join(f'if(x == "fixture-code-{index}")allow()' for index in range(6))
        findings = analyzer.analyze(source, "https://synthetic.invalid/")
        self.assertEqual(analyzer.used, 2)
        self.assertEqual(analyzer.completed, 1)
        self.assertFalse(analyzer.failed)
        self.assertTrue(any(f.title == "Local AI output truncated" for f in findings))
        self.assertTrue(any(f.category == "Local AI" for f in findings))
        self.assertFalse(any("runtime/model unavailable" in f.evidence for f in findings))


if __name__ == "__main__":
    unittest.main()
