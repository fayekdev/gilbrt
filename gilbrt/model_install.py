"""Explicit model installation with conservative CPU memory recommendations."""

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass

from rich.console import Console
from rich.prompt import Prompt

from .bundled_ai import RUNTIME, available_memory_bytes

GIB = 1024 ** 3


@dataclass(frozen=True)
class Model:
    key: str
    download: str
    ram_gib: float


# Download estimates: https://ollama.com/library/qwen2.5-coder.
# RAM thresholds are gilbrt estimates including inference/application headroom.
MODELS = (
    Model("bundled", "469 MiB + CPU runtime", 1.5),
    Model("ollama:qwen2.5-coder:0.5b", "398 MB", 2),
    Model("ollama:qwen2.5-coder:1.5b", "986 MB", 3),
    Model("ollama:qwen2.5-coder:3b", "1.9 GB", 5),
    Model("ollama:qwen2.5-coder:7b", "4.7 GB", 9),
)


def unavailable_reason(model: Model, memory: int | None, ollama: str | None) -> str:
    """Explain why a model cannot be recommended on this machine now."""
    if model.key == "bundled":
        if platform.system() not in {"Windows", "Linux"} or platform.machine().lower() not in {
            "amd64", "x86_64", "arm64", "aarch64"
        }:
            return "bundled runtime requires Windows/Linux x64 or arm64"
    elif not ollama:
        return "install Ollama first: https://ollama.com/download"
    if memory is None:
        return "available RAM could not be detected"
    if memory < model.ram_gib * GIB:
        return "insufficient available RAM for our conservative estimate"
    return ""


def manage_models(selection: str | None, console: Console) -> int:
    """List hardware fit, optionally prompt, and install only an explicit choice."""
    memory = available_memory_bytes()
    ollama = shutil.which("ollama")
    console.print(f"Machine: {platform.system()} {platform.machine()}, {os.cpu_count() or 1} logical CPUs", markup=False)
    console.print("Available RAM: " + (f"{memory / GIB:.1f} GiB" if memory is not None else "unknown"))
    console.print("CPU/RAM estimates; speed and actual memory use vary with context and other apps.")
    reasons = {m.key: unavailable_reason(m, memory, ollama) for m in MODELS}
    suitable = [m for m in MODELS if not reasons[m.key]]
    recommended = suitable[-1].key if suitable else None
    for model in MODELS:
        status = reasons[model.key] or ("recommended" if model.key == recommended else "should fit")
        console.print(f"  {model.key}: download ~{model.download}; available RAM estimate {model.ram_gib:g} GiB — {status}", markup=False)
    if selection is None:
        return 0
    if selection == "choose":
        if not suitable:
            console.print("No model recommended right now. Free RAM or install a supported runtime, then retry.", style="yellow")
            return 1
        if not sys.stdin.isatty():
            console.print("Choose explicitly in scripts: gilbrt --install-models MODEL (see --list-models).", style="yellow")
            return 1
        selection = Prompt.ask("Model to download (cancel to exit)", choices=[m.key for m in suitable] + ["cancel"],
                               default=recommended, console=console)
        if selection == "cancel":
            return 0
    if selection not in reasons:
        raise ValueError("Unknown model. Use --list-models to see supported choices.")
    if reasons[selection]:
        raise ValueError(f"Cannot recommend {selection}: {reasons[selection]}")
    if selection == "bundled":
        from .model_download import install
        install()
        tag = "bundled"
    else:
        tag = selection.removeprefix("ollama:")
        result = subprocess.run([ollama, "pull", tag], check=False)
        if result.returncode:
            raise RuntimeError("Ollama download failed. Check that the local Ollama server is running, then retry.")
        RUNTIME.mkdir(parents=True, exist_ok=True)
        (RUNTIME / "default_model.txt").write_text(tag + "\n", encoding="utf-8")
    console.print(f"Installed and selected {tag}. Enable local-ai in gilbrt, or use --local-model {tag}.", markup=False)
    return 0
