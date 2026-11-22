#!/usr/bin/env bash
# Start the guided audit from a checkout without PowerShell or venv activation.
set -euo pipefail
project_dir="$(cd -P "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$project_dir/bin/gilbrt" "$@"
