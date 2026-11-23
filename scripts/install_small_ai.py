"""Compatibility entry point for the packaged, checksum-verified installer."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gilbrt.model_download import install


if __name__ == "__main__":
    install()
