#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/p4/build"

: "${SDE:?Environment variable SDE is not set}"
: "${SDE_INSTALL:?Environment variable SDE_INSTALL is not set}"

if [[ ! -d "$BUILD_DIR" ]]; then
    echo "P4 build directory not found: $BUILD_DIR" >&2
    echo "Run p4/scripts/build.sh first." >&2
    exit 1
fi

cd "$BUILD_DIR"
make uninstall
make install
