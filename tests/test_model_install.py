"""Hardware recommendations and explicit install routing without downloads."""

import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rich.console import Console

from gilbrt import model_install as models
from gilbrt.cli import installed_model_default, main


class ModelInstallTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.console = Console(file=self.output, width=180)
        for name, value in (("available_memory_bytes", 6 * models.GIB), ("shutil.which", "ollama"),
                            ("platform.system", "Linux"), ("platform.machine", "x86_64")):
            mock = patch("gilbrt.model_install." + name, return_value=value)
            mock.start()
            self.addCleanup(mock.stop)

    def test_preview_recommends_fitting_model_without_download(self):
        with patch.object(models.subprocess, "run") as run:
            self.assertEqual(models.manage_models(None, self.console), 0)
        run.assert_not_called()
        self.assertIn("ollama:qwen2.5-coder:3b", self.output.getvalue())
        self.assertIn("recommended", self.output.getvalue())

    def test_low_or_unknown_ram_blocks_install(self):
        for memory in (None, 256 * 1024 ** 2):
            with self.subTest(memory=memory), patch.object(models, "available_memory_bytes", return_value=memory):
                with self.assertRaises(ValueError), patch("gilbrt.model_download.install") as install:
                    models.manage_models("bundled", self.console)
                install.assert_not_called()

    def test_missing_ollama_recommends_bundled(self):
        with patch.object(models.shutil, "which", return_value=None):
            self.assertEqual(models.manage_models(None, self.console), 0)
        self.assertIn("1.5 GiB — recommended", self.output.getvalue())

    def test_unsupported_bundled_architecture(self):
        with patch.object(models.platform, "machine", return_value="riscv64"):
            self.assertTrue(models.unavailable_reason(models.MODELS[0], 6 * models.GIB, None))

    def test_successful_pull_saves_default_and_failure_preserves_it(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            with patch.object(models, "RUNTIME", runtime), patch.object(models.subprocess, "run") as run:
                run.return_value.returncode = 0
                self.assertEqual(models.manage_models("ollama:qwen2.5-coder:1.5b", self.console), 0)
                run.assert_called_once_with(["ollama", "pull", "qwen2.5-coder:1.5b"], check=False)
                run.return_value.returncode = 1
                with self.assertRaises(RuntimeError):
                    models.manage_models("ollama:qwen2.5-coder:3b", self.console)
            with patch("gilbrt.cli.RUNTIME", runtime):
                self.assertEqual(installed_model_default(), "qwen2.5-coder:1.5b")

    def test_bundled_uses_verified_packaged_installer(self):
        with patch("gilbrt.model_download.install") as install:
            self.assertEqual(models.manage_models("bundled", self.console), 0)
        install.assert_called_once_with()

    def test_no_unattended_download_or_unknown_model(self):
        with patch.object(models.sys.stdin, "isatty", return_value=False), patch.object(models.subprocess, "run") as run:
            self.assertEqual(models.manage_models("choose", self.console), 1)
            with self.assertRaises(ValueError):
                models.manage_models("ollama:arbitrary;command", self.console)
        run.assert_not_called()

    def test_cli_routes_without_audit_authorization_or_url(self):
        with patch.object(models, "manage_models", return_value=0) as manage:
            self.assertEqual(main(["--list-models"]), 0)
            self.assertIsNone(manage.call_args.args[0])
            self.assertEqual(main(["--install-models"]), 0)
            self.assertEqual(manage.call_args.args[0], "choose")

    def test_prompt_cancellation(self):
        with patch.object(models.sys.stdin, "isatty", return_value=True), patch.object(models.Prompt, "ask", return_value="cancel"):
            self.assertEqual(models.manage_models("choose", self.console), 0)
