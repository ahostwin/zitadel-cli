#!/usr/bin/env bash
set -euo pipefail

# Find the golangci-lint binary in runfiles
SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
RUNFILES="${SCRIPT_DIR}/lint.runfiles"

LINT_BIN=""
for dir in "$RUNFILES"/*/; do
    if [[ -x "${dir}golangci-lint" ]]; then
        LINT_BIN="${dir}golangci-lint"
        break
    fi
done

if [[ -z "$LINT_BIN" ]]; then
    echo "Error: golangci-lint not found in runfiles" >&2
    exit 1
fi

cd "$BUILD_WORKSPACE_DIRECTORY"
exec "$LINT_BIN" run "$@"
