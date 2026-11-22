#!/usr/bin/env bash
# Per-user Bash install: Python application plus optional explicit small-AI setup.
set -euo pipefail
project_dir="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_prefix="${HOME}/.local"
with_ai=0
add_path=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ai) with_ai=1; shift ;;
    --add-path) add_path=1; shift ;;
    --prefix)
      [[ $# -ge 2 && -n "$2" ]] || { printf '%s\n' '--prefix requires a directory' >&2; exit 2; }
      install_prefix="$2"; shift 2 ;;
    -h|--help)
      printf '%s\n' 'Usage: bash install.sh [--with-ai] [--add-path] [--prefix DIRECTORY]' \
        'Default: install gilbrt into ~/.local/bin; --with-ai installs the small model; --add-path configures Bash PATH.'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) python_suffix='Scripts/python.exe' ;;
  *) python_suffix='bin/python' ;;
esac
environment_dir="$project_dir/.venv"
if [[ ! -x "$environment_dir/$python_suffix" ]]; then
  environment_dir="$project_dir/.venv-bash"
fi
if [[ ! -x "$environment_dir/$python_suffix" ]]; then
  bootstrap_python=''
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      bootstrap_python="$candidate"; break
    fi
  done
  [[ -n "$bootstrap_python" ]] || { printf '%s\n' 'Python 3.10+ with venv is required.' >&2; exit 1; }
  "$bootstrap_python" -m venv "$environment_dir"
fi
environment_python="$environment_dir/$python_suffix"
"$environment_python" -m pip install -e "$project_dir"
if [[ "$with_ai" -eq 1 ]]; then
  "$environment_python" "$project_dir/scripts/install_small_ai.py"
fi
install_bin="$install_prefix/bin"
mkdir -p "$install_bin"
launcher_text="$(printf '#!/usr/bin/env bash\n# gilbrt generated launcher\nexec %q "$@"\n' "$project_dir/bin/gilbrt")"
if [[ -e "$install_bin/gilbrt" || -L "$install_bin/gilbrt" ]]; then
  [[ -f "$install_bin/gilbrt" && "$(cat "$install_bin/gilbrt")" == "$launcher_text" ]] || {
    printf 'An existing command occupies %s; choose another --prefix.\n' "$install_bin/gilbrt" >&2
    exit 1
  }
fi
printf '%s\n' "$launcher_text" > "$install_bin/gilbrt"
chmod +x "$install_bin/gilbrt"
chmod +x "$project_dir/bin/gilbrt"
chmod +x "$project_dir/gilbrt.sh"
if [[ "$add_path" -eq 1 ]]; then
  path_command="$(printf 'export PATH=%q:"$PATH"' "$install_bin")"
  printf '%s\n' "$path_command" | "$environment_python" "$project_dir/scripts/install_bash_path.py" "$HOME/.bashrc"
fi
printf 'Installed: %s/gilbrt\n' "$install_bin"
case ":${PATH}:" in
  *":${install_bin}:"*) printf '%s\n' 'Run: gilbrt' ;;
  *) printf 'Add %s to PATH, then run gilbrt.\n' "$install_bin" ;;
esac
