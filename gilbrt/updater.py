"""Conservative self-update support for Git-based gilbrt installations."""

import subprocess
import sys
from pathlib import Path


def _run(arguments: list[str], root: Path) -> str:
    try:
        completed = subprocess.run(arguments, cwd=root, text=True, capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise OSError("Update command failed") from error
    if completed.returncode:
        raise OSError("Update command failed")
    return completed.stdout.strip()


def update_installation() -> str:
    """Fast-forward a clean checkout and refresh its editable installation."""
    root = Path(__file__).resolve().parents[1]
    if not (root / ".git").is_dir() or not (root / "pyproject.toml").is_file():
        raise ValueError("gilbrt is not running from a Git source installation")
    if _run(["git", "status", "--porcelain", "--untracked-files=no"], root):
        raise ValueError("tracked local changes must be preserved")
    before = _run(["git", "rev-parse", "--verify", "HEAD"], root)
    _run(["git", "pull", "--ff-only"], root)
    _run([sys.executable, "-m", "pip", "install", "-e", str(root)], root)
    after = _run(["git", "rev-parse", "--verify", "HEAD"], root)
    return "gilbrt is already up to date." if before == after else f"gilbrt updated to {after[:7]}."
