"""Add an installer-generated PATH block to Bash startup files, preserving backups."""

import re
import shutil
import sys
from pathlib import Path

START = b"# >>> gilbrt PATH >>>"
END = b"# <<< gilbrt PATH <<<"


def configure(bashrc: Path, path_command: bytes) -> None:
    """Insert only the owned PATH block; create a login loader for fresh Bash homes."""
    if bashrc.name != ".bashrc" or not path_command.startswith(b"export PATH=") or b"\n" in path_command:
        raise ValueError("Expected a .bashrc target and one installer-generated export command")
    original = bashrc.read_bytes() if bashrc.exists() else b""
    block = START + b"\n" + path_command + b"\n" + END + b"\n"
    if START in original:
        expression = rb"(?ms)^" + re.escape(START) + rb"\r?\n.*?^" + re.escape(END) + rb"\r?\n?"
        if not re.search(expression, original):
            raise ValueError("Existing managed Bash PATH block is incomplete")
        updated = re.sub(expression, lambda _match: block, original)
    else:
        updated = original + (b"\n" if original and not original.endswith(b"\n") else b"") + block
    if updated != original:
        backup = bashrc.with_name(".bashrc.gilbrt.bak")
        if bashrc.exists() and not backup.exists():
            shutil.copy2(bashrc, backup)
        bashrc.write_bytes(updated)
    home = bashrc.parent
    if not any((home / name).exists() for name in (".bash_profile", ".bash_login", ".profile")):
        (home / ".bash_profile").write_bytes(
            b'# Bash login setup created by gilbrt\nif [ -f "$HOME/.bashrc" ]; then\n  . "$HOME/.bashrc"\nfi\n')


if __name__ == "__main__":
    configure(Path(sys.argv[1]), sys.stdin.buffer.read().rstrip(b"\r\n"))
    print("Bash PATH configured. Open a new Bash terminal or run: source ~/.bashrc")
