#!/usr/bin/env bash
# Download a persistent checkout, then invoke gilbrt's own installer.
set -euo pipefail

if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then
  printf '%s\n' 'Usage: bash install.sh [--with-ai] [--ai-model bundled|ollama:TAG] [--add-path] [--prefix DIRECTORY]' \
    'Requires Git, Python 3.10+ and venv. Installs without sudo.' \
    'GILBRT_SOURCE_URL overrides the Git remote (for authenticated SSH access).' \
    'GILBRT_INSTALL_DIR overrides the new checkout directory.'
  exit 0
fi

case "$(uname -s)" in
  Linux|Darwin) ;;
  *) printf '%s\n' 'Use the Windows PowerShell instructions on the website.' >&2; exit 1 ;;
esac
with_ai=0
args=("$@")
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ai) with_ai=1; shift ;;
    --ai-model) [[ $# -ge 2 && -n "$2" ]] || { printf '%s\n' '--ai-model requires a value' >&2; exit 2; }; with_ai=1; shift 2 ;;
    --add-path) shift ;;
    --prefix) [[ $# -ge 2 && -n "$2" ]] || { printf '%s\n' '--prefix requires a directory' >&2; exit 2; }; shift 2 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if [[ "$(uname -s)" == Darwin && "$with_ai" == 1 ]]; then
  printf '%s\n' 'The bundled AI runtime supports Windows/Linux only. Omit --with-ai on macOS.' >&2
  exit 2
fi
command -v git >/dev/null || { printf '%s\n' 'Install Git first.' >&2; exit 1; }
bootstrap_python=''
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys, venv; sys.exit(sys.version_info < (3, 10))' 2>/dev/null; then
    bootstrap_python="$candidate"; break
  fi
done
[[ -n "$bootstrap_python" ]] || { printf '%s\n' 'Install Python 3.10+ with venv support first (Debian/Ubuntu: python3-venv).' >&2; exit 1; }
install_dir="${GILBRT_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/gilbrt}"
[[ "$install_dir" == /* ]] || { printf '%s\n' 'GILBRT_INSTALL_DIR must be an absolute path.' >&2; exit 2; }
if [[ -e "$install_dir" || -L "$install_dir" ]]; then
  printf 'Destination already exists: %s\nChoose a new GILBRT_INSTALL_DIR or use the existing checkout.\n' "$install_dir" >&2
  if [[ -f "$install_dir/install.sh" && -f "$install_dir/pyproject.toml" ]]; then
    printf 'To retry your existing gilbrt checkout without deleting it:\n  bash %q --add-path\n' "$install_dir/install.sh" >&2
  fi
  exit 1
fi
mkdir -p "$(dirname "$install_dir")"
printf '%s\n' 'Downloading gilbrt from GitHub…'
git clone --depth 1 -- "${GILBRT_SOURCE_URL:-https://github.com/fayekdev/gilbrt.git}" "$install_dir" || {
  printf '%s\n' 'Download failed. Check repository visibility or configure Git credentials / GILBRT_SOURCE_URL.' >&2
  exit 1
}
bash "$install_dir/install.sh" "${args[@]}"
printf '\n%s\n' 'Installation complete. For automated audits, pass --url and --confirm-authorized.'
