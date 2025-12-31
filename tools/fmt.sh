#!/usr/bin/env bash
set -euo pipefail

# Find the gofumpt binary in runfiles
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
RUNFILES="${SCRIPT_DIR}/fmt.runfiles"

FMT_BIN=""
for dir in "$RUNFILES"/*/; do
    if [[ -x "${dir}gofumpt" ]]; then
        FMT_BIN="${dir}gofumpt"
        break
    elif [[ -x "${dir}file/gofumpt" ]]; then
        FMT_BIN="${dir}file/gofumpt"
        break
    fi
done

if [[ -z "$FMT_BIN" ]]; then
    echo "Error: gofumpt not found in runfiles" >&2
    exit 1
fi

cd "$BUILD_WORKSPACE_DIRECTORY"
exec "$FMT_BIN" -extra -w .
