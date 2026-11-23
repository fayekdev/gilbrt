"""Install pinned CPU-only llama.cpp and a checksum-verified small Qwen GGUF.

Run explicitly; normal audits never download executables or model weights.
"""

import hashlib
import json
import os
import platform
import stat
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

from .bundled_ai import RUNTIME

ROOT = Path(__file__).resolve().parents[1]
DEST = RUNTIME
RELEASE = "b12633"
REVISION = "ebb2015119c907b064c512bf053e945850b5875f"
MODEL = "qwen2.5-coder-0.5b-instruct-q4_k_m.gguf"
MODEL_SHA = "1d9614638d18024d0fbb36575a15f1302a3adf044df10345688ec4f6e1c4ff32"
MODEL_SIZE = 491400064


def digest(path: Path) -> str:
    """Hash a file with bounded memory."""
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def download(url: str, target: Path, expected: str, size: int) -> None:
    """Stream and retry a resumable download, verifying the complete SHA-256."""
    if target.is_file() and target.stat().st_size == size and digest(target) == expected:
        print(f"Already verified: {target.name}", flush=True)
        return
    partial = target.with_suffix(target.suffix + ".part")
    for attempt in range(5):
        offset = partial.stat().st_size if partial.exists() else 0
        request = urllib.request.Request(url, headers={"User-Agent": "gilbrt-installer/0.1", "Range": f"bytes={offset}-"})
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                append = response.status == 206 and offset > 0
                if append and not response.headers.get("Content-Range", "").startswith(f"bytes {offset}-"):
                    raise ValueError("Unexpected download range")
                count = offset if append else 0
                last_percent = -1
                with partial.open("ab" if append else "wb") as output:
                    while block := response.read(1024 * 1024):
                        output.write(block)
                        count += len(block)
                        if count > size:
                            raise ValueError("Download exceeded expected size")
                        percent = count * 100 // size // 10 * 10
                        if percent != last_percent:
                            print(f"{target.name}: {percent}%", flush=True)
                            last_percent = percent
            if partial.stat().st_size != size or digest(partial) != expected:
                partial.unlink(missing_ok=True)
                raise ValueError("Download checksum or size mismatch")
            partial.replace(target)
            print(f"Verified: {target.name}", flush=True)
            return
        except (OSError, ValueError) as error:
            if attempt == 4:
                raise RuntimeError(f"Could not download {target.name}") from error
            print(f"Download interrupted; retry {attempt + 1}/4", flush=True)
            time.sleep(2)


def install() -> None:
    """Install assets for the current supported platform without changing PATH."""
    machine = platform.machine().lower()
    arch = "arm64" if machine in {"arm64", "aarch64"} else "x64" if machine in {"amd64", "x86_64"} else None
    if arch is None or platform.system() not in {"Windows", "Linux"}:
        raise RuntimeError("Prebuilt small-AI installation currently supports Windows/Linux x64 and arm64")
    DEST.mkdir(parents=True, exist_ok=True)
    suffix = f"-bin-win-cpu-{arch}.zip" if os.name == "nt" else f"-bin-ubuntu-{arch}.tar.gz"
    with urllib.request.urlopen(f"https://api.github.com/repos/ggml-org/llama.cpp/releases/tags/{RELEASE}", timeout=30) as response:
        release = json.load(response)
    asset = next(item for item in release["assets"] if item["name"].endswith(suffix))
    checksum = asset.get("digest", "")
    if not checksum.startswith("sha256:"):
        raise RuntimeError("Official runtime checksum unavailable")
    archive = DEST / asset["name"]
    download(asset["browser_download_url"], archive, checksum.removeprefix("sha256:"), asset["size"])
    runtime = DEST / "llama"
    runtime.mkdir(exist_ok=True)
    base = runtime.resolve()
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as zipped:
            for info in zipped.infolist():
                target = (base / info.filename).resolve()
                if not target.is_relative_to(base) or stat.S_ISLNK(info.external_attr >> 16):
                    raise RuntimeError("Unsafe runtime archive member")
            zipped.extractall(base)
    else:
        with tarfile.open(archive) as tar:
            for member in tar.getmembers():
                target = (base / member.name).resolve()
                link_target = ((target.parent / member.linkname) if member.issym() else (base / member.linkname)).resolve()
                if not target.is_relative_to(base) or ((member.issym() or member.islnk()) and not link_target.is_relative_to(base)):
                    raise RuntimeError("Unsafe runtime archive member")
            # Explicit validation above supports Python 3.10 as well as newer tar filters.
            tar.extractall(base)
    model = DEST / MODEL
    download(f"https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF/resolve/{REVISION}/{MODEL}",
             model, MODEL_SHA, MODEL_SIZE)
    executable = next(runtime.rglob("llama-server.exe" if os.name == "nt" else "llama-server"), None)
    if not executable:
        raise RuntimeError("Downloaded runtime contains no llama-server")
    manifest = {"runtime_release": RELEASE, "runtime_sha256": checksum.removeprefix("sha256:"),
                "server": str(executable.relative_to(DEST)), "model": MODEL, "model_sha256": MODEL_SHA,
                "model_bytes": MODEL_SIZE, "model_revision": REVISION,
                "source": "https://huggingface.co/Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF"}
    (DEST / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (DEST / "default_model.txt").write_text("bundled\n", encoding="utf-8")
    print("Small local model installed. Select local-ai and use model name bundled.", flush=True)


if __name__ == "__main__":
    install()
