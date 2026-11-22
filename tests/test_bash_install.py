"""Preserve user configuration while installing a Bash command PATH entry."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("install_bash_path", Path(__file__).resolve().parents[1] / "scripts" / "install_bash_path.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BashInstallTests(unittest.TestCase):
    """Check fresh setup, preserved bytes, repeat installation and malformed blocks."""

    def test_fresh_bash_home_gets_command_path_and_login_loader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            MODULE.configure(home / ".bashrc", b'export PATH=/test/bin:"$PATH"')
            self.assertIn(b'export PATH=/test/bin:"$PATH"', (home / ".bashrc").read_bytes())
            self.assertIn(b'. "$HOME/.bashrc"', (home / ".bash_profile").read_bytes())

    def test_existing_configuration_is_preserved_and_backed_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            original = b"# Existing settings\xff\r\nexport CUSTOM=value\r\n"
            (home / ".bashrc").write_bytes(original)
            (home / ".profile").write_bytes(b"# Existing login settings\n")
            MODULE.configure(home / ".bashrc", b'export PATH=/test/bin:"$PATH"')
            self.assertTrue((home / ".bashrc").read_bytes().startswith(original))
            self.assertEqual((home / ".bashrc.gilbrt.bak").read_bytes(), original)
            self.assertEqual((home / ".profile").read_bytes(), b"# Existing login settings\n")
            self.assertFalse((home / ".bash_profile").exists())

    def test_repeated_install_updates_only_one_owned_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rc = Path(directory) / ".bashrc"
            MODULE.configure(rc, b'export PATH=/first/bin:"$PATH"')
            first = rc.read_bytes()
            MODULE.configure(rc, b'export PATH=/first/bin:"$PATH"')
            self.assertEqual(rc.read_bytes(), first)
            MODULE.configure(rc, b'export PATH=/second/bin:"$PATH"')
            self.assertEqual(rc.read_bytes().count(MODULE.START), 1)
            self.assertNotIn(b"/first/bin", rc.read_bytes())

    def test_incomplete_owned_block_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            rc = Path(directory) / ".bashrc"
            original = MODULE.START + b"\n# unfinished\n"
            rc.write_bytes(original)
            with self.assertRaises(ValueError):
                MODULE.configure(rc, b'export PATH=/test/bin:"$PATH"')
            self.assertEqual(rc.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
