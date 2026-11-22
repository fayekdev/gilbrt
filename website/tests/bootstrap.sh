#!/usr/bin/env bash
# Offline integration checks: fake only platform, Python and Git; use real Bash/files.
set -euo pipefail
script="$(cd "$(dirname "$0")/../public" && pwd)/install.sh"
fixture="$(mktemp -d)"
trap 'rm -f "$fixture/checkout/install.sh" "$fixture/receipt" "$fixture/output"; rmdir "$fixture/checkout" "$fixture" 2>/dev/null || true' EXIT
export GILBRT_INSTALL_DIR="$fixture/checkout"
export BOOTSTRAP_RECEIPT="$fixture/receipt"
export BOOTSTRAP_PLATFORM=Linux
uname() { printf '%s\n' "$BOOTSTRAP_PLATFORM"; }
python3() { return 0; }
git() {
  [[ "$1" == clone && "$2" == --depth && "$3" == 1 && "$4" == -- ]]
  [[ "$5" == 'https://github.com/fayekdev/gilbrt.git' ]]
  mkdir -p "$6"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$@" > "$BOOTSTRAP_RECEIPT"' > "$6/install.sh"
}
export -f uname python3 git
bash "$script" --with-ai --add-path --prefix "$fixture/prefix" > "$fixture/output"
[[ "$(cat "$fixture/receipt")" == "$(printf '%s\n' --with-ai --add-path --prefix "$fixture/prefix")" ]]
printf '%s\n' 'PASS: clone and installer argument forwarding'
if bash "$script" > "$fixture/output" 2>&1; then exit 1; fi
grep -q 'Destination already exists' "$fixture/output"
printf '%s\n' 'PASS: existing checkout is preserved'
export BOOTSTRAP_PLATFORM=Darwin
if bash "$script" --with-ai > "$fixture/output" 2>&1; then exit 1; fi
grep -q 'Omit --with-ai on macOS' "$fixture/output"
printf '%s\n' 'PASS: unsupported macOS bundled AI is rejected'
export BOOTSTRAP_PLATFORM=Linux
if bash "$script" --prefix > "$fixture/output" 2>&1; then exit 1; fi
grep -q 'requires a directory' "$fixture/output"
printf '%s\n' 'PASS: missing prefix is rejected'
if bash "$script" --unknown > "$fixture/output" 2>&1; then exit 1; fi
grep -q 'Unknown option' "$fixture/output"
printf '%s\n' 'PASS: unknown option is rejected'
