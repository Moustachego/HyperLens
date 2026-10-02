#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/p4/build"
P4_SOURCE="$PROJECT_ROOT/p4/data_plane/tofino2.p4"

: "${SDE:?Environment variable SDE is not set}"
: "${SDE_INSTALL:?Environment variable SDE_INSTALL is not set}"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake "$SDE/p4studio/" \
    -DTOFINO=OFF \
    -DTOFINO2=ON \
    -DCMAKE_INSTALL_PREFIX="$SDE_INSTALL" \
    -DCMAKE_MODULE_PATH="$SDE/cmake" \
    -DP4_NAME=tofino2 \
    -DP4_PATH="$P4_SOURCE"
make tofino2
