#!/usr/bin/env bash
# Per-user Bash install: Python application plus optional explicit small-AI setup.
set -euo pipefail
project_dir="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_prefix="${HOME}/.local"
with_ai=0
ai_model=''
add_path=0
relink_only=0

write_launcher() {
  local install_bin command_path launcher_text backup temporary
  local -a existing_lines=()
  install_bin="$install_prefix/bin"
  mkdir -p "$install_bin"
  command_path="$install_bin/gilbrt"
  launcher_text="$(printf '#!/usr/bin/env bash\n# gilbrt generated launcher\nexec %q "$@"\n' "$project_dir/bin/gilbrt")"
  if [[ -e "$command_path" || -L "$command_path" ]]; then
    if [[ -L "$command_path" || ! -f "$command_path" ]]; then
      printf 'An unrelated command occupies %s; choose another --prefix.\n' "$command_path" >&2
      return 1
    fi
    if [[ "$(cat "$command_path")" != "$launcher_text" ]]; then
      mapfile -t existing_lines < "$command_path"
      if [[ ${#existing_lines[@]} -ne 3 || "${existing_lines[0]-}" != '#!/usr/bin/env bash' ||
            "${existing_lines[1]-}" != '# gilbrt generated launcher' ||
            "${existing_lines[2]-}" != exec\ *'"$@"' ]]; then
        printf 'An unrelated command occupies %s; choose another --prefix.\n' "$command_path" >&2
        return 1
      fi
      # Recognize our three-line launcher without evaluating its old target.
      # Preserve a unique backup before repairing a moved/deleted checkout path.
      backup="$(mktemp "$install_bin/gilbrt.backup.XXXXXX")"
      cp -p -- "$command_path" "$backup"
      printf 'Previous launcher backed up: %s\n' "$backup"
    fi
  fi
  temporary="$(mktemp "$install_bin/.gilbrt-launcher.XXXXXX")"
  if ! { printf '%s\n' "$launcher_text" > "$temporary" && chmod +x "$temporary" && mv -f -- "$temporary" "$command_path"; }; then
    rm -f -- "$temporary"
    return 1
  fi
  chmod +x "$project_dir/bin/gilbrt" "$project_dir/gilbrt.sh"
  printf 'Installed: %s\nTarget checkout: %s\n' "$command_path" "$project_dir"
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-ai) with_ai=1; shift ;;
    --ai-model)
      [[ $# -ge 2 && -n "$2" ]] || { printf '%s\n' '--ai-model requires bundled or ollama:TAG' >&2; exit 2; }
      with_ai=1; ai_model="$2"; shift 2 ;;
    --add-path) add_path=1; shift ;;
    --relink) relink_only=1; shift ;;
    --prefix)
      [[ $# -ge 2 && -n "$2" ]] || { printf '%s\n' '--prefix requires a directory' >&2; exit 2; }
      install_prefix="$2"; shift 2 ;;
    -h|--help)
      printf '%s\n' 'Usage: bash install.sh [--with-ai] [--ai-model bundled|ollama:TAG] [--add-path] [--prefix DIRECTORY] [--relink]' \
        'Default: install gilbrt into ~/.local/bin; AI selection is explicit; --add-path configures Bash PATH.' \
        '--relink only repairs the command target to this checkout; it does not install Python dependencies or models.'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if [[ "$relink_only" -eq 1 ]]; then
  if [[ "$with_ai" -eq 1 || "$add_path" -eq 1 ]]; then
    printf '%s\n' '--relink cannot be combined with --with-ai, --ai-model or --add-path; run a normal install for those changes.' >&2
    exit 2
  fi
  write_launcher
  printf '%s\n' 'Run: hash -r' 'Then: gilbrt --gui --no-browser' 'If this checkout has no Python environment yet, run: bash install.sh'
  exit 0
fi
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
  if ! "$bootstrap_python" -m venv "$environment_dir"; then
    printf '%s\n' 'Could not create the Python virtual environment.' \
      'On Debian/Ubuntu, install python3-venv (and the matching version package for a custom Python), then rerun this installer.' >&2
    exit 1
  fi
fi
environment_python="$environment_dir/$python_suffix"
if ! "$environment_python" -m pip --version >/dev/null 2>&1; then
  printf '%s\n' 'Repairing pip in the existing virtual environment…'
  if ! "$environment_python" -m ensurepip --upgrade; then
    printf '%s\n' 'This virtual environment has no usable pip/ensurepip.' \
      'On Debian/Ubuntu, install python3-venv for this Python version, then rerun this installer. The checkout is preserved.' >&2
    exit 1
  fi
fi
"$environment_python" -m pip install -e "$project_dir"
if [[ "$with_ai" -eq 1 ]]; then
  if [[ -z "$ai_model" && -t 0 ]]; then
    printf '%s\n' 'Choose the local AI model:' \
      '  1) bundled — Qwen2.5-Coder 0.5B Q4, recommended for about 2 GB RAM' \
      '  2) ollama:qwen2.5-coder:0.5b — use Ollama (must already be installed)'
    read -r -p 'Selection [1]: ' selection
    case "${selection:-1}" in
      1) ai_model='bundled' ;;
      2) ai_model='ollama:qwen2.5-coder:0.5b' ;;
      *) printf '%s\n' 'Invalid AI model selection.' >&2; exit 2 ;;
    esac
  fi
  ai_model="${ai_model:-bundled}"
  mkdir -p "$project_dir/.runtime"
  case "$ai_model" in
    bundled)
      "$environment_python" "$project_dir/scripts/install_small_ai.py" ;;
    ollama:*)
      model_tag="${ai_model#ollama:}"
      [[ "$model_tag" =~ ^[A-Za-z0-9._/-]+:[A-Za-z0-9._-]+$ ]] || { printf '%s\n' 'Invalid Ollama model tag.' >&2; exit 2; }
      command -v ollama >/dev/null || { printf '%s\n' 'Ollama is not installed; choose bundled or install Ollama first.' >&2; exit 1; }
      ollama pull "$model_tag"
      printf '%s\n' "$model_tag" > "$project_dir/.runtime/default_model.txt" ;;
    *) printf '%s\n' '--ai-model must be bundled or ollama:TAG' >&2; exit 2 ;;
  esac
fi
write_launcher
install_bin="$install_prefix/bin"
if [[ "$add_path" -eq 1 ]]; then
  path_command="$(printf 'export PATH=%q:"$PATH"' "$install_bin")"
  printf '%s\n' "$path_command" | "$environment_python" "$project_dir/scripts/install_bash_path.py" "$HOME/.bashrc"
fi
case ":${PATH}:" in
  *":${install_bin}:"*) printf '%s\n' 'Run: gilbrt' ;;
  *) printf 'Add %s to PATH, then run gilbrt.\n' "$install_bin" ;;
esac
