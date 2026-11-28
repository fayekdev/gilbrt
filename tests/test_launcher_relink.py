"""Run the real Bash relinker against stale launcher and path-with-spaces fixtures."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def bash_path():
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            candidate = Path(git).resolve().parents[1] / "bin" / "bash.exe"
            if candidate.is_file():
                return str(candidate)
        return None
    return shutil.which("bash")


@unittest.skipUnless(bash_path(), "Bash/Git Bash is required")
class LauncherRelinkTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".runtime"
        scratch.mkdir(exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.checkout = self.root / "current checkout with spaces"
        self.prefix = self.root / "install prefix with spaces"
        (self.checkout/"bin").mkdir(parents=True)
        (self.checkout/"install.sh").write_bytes((ROOT/"install.sh").read_bytes())
        (self.checkout/"bin"/"gilbrt").write_bytes(b'#!/usr/bin/env bash\nprintf "%s\\n" "$@"\n')
        (self.checkout/"gilbrt.sh").write_bytes(b'#!/usr/bin/env bash\nexit 0\n')
        (self.prefix/"bin").mkdir(parents=True)
        self.command = self.prefix/"bin"/"gilbrt"

    def relink(self, *flags):
        return subprocess.run([bash_path(),"install.sh","--relink","--prefix",self.prefix.as_posix(),*flags],
                              cwd=self.checkout,capture_output=True,text=True,timeout=20)

    def test_stale_owned_launcher_is_backed_up_and_arguments_are_preserved(self):
        old = b'#!/usr/bin/env bash\n# gilbrt generated launcher\nexec /root/.local/share/gilbrt/bin/gilbrt "$@"\n'
        self.command.write_bytes(old)
        result = self.relink()
        self.assertEqual(result.returncode,0,result.stderr)
        backups = list(self.command.parent.glob("gilbrt.backup.*"))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),old)
        self.assertNotIn(b"/root/.local/share",self.command.read_bytes())
        launched = subprocess.run([bash_path(),self.command.as_posix(),"--gui","--no-browser","file with spaces","literal$HOME"],
                                  capture_output=True,text=True,timeout=10)
        self.assertEqual(launched.returncode,0,launched.stderr)
        self.assertEqual(launched.stdout.splitlines(),["--gui","--no-browser","file with spaces","literal$HOME"])
        self.assertFalse((self.checkout/".venv-bash").exists())
        self.assertFalse((self.checkout/".runtime").exists())
        again = self.relink()
        self.assertEqual(again.returncode,0,again.stderr)
        self.assertEqual(list(self.command.parent.glob("gilbrt.backup.*")),backups)

    def test_fresh_command_can_be_linked_without_installing_dependencies(self):
        result = self.relink()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn(b"# gilbrt generated launcher",self.command.read_bytes())
        self.assertFalse((self.checkout/".venv-bash").exists())

    def test_unrelated_or_modified_commands_are_not_overwritten(self):
        for original in (b'#!/bin/sh\necho unrelated\n',
                         b'#!/usr/bin/env bash\n# gilbrt generated launcher\nexec /old/path "$@"\necho custom\n'):
            self.command.write_bytes(original)
            result = self.relink()
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(self.command.read_bytes(),original)
            self.assertEqual(list(self.command.parent.glob("gilbrt.backup.*")),[])

    def test_relink_rejects_ambiguous_install_options_before_changing_command(self):
        for flag in ("--with-ai","--add-path"):
            result = self.relink(flag)
            self.assertEqual(result.returncode,2)
            self.assertFalse(self.command.exists())


if __name__=="__main__":
    unittest.main()
