#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
cd "$PROJECT_ROOT"
mkdir -p "$PROJECT_ROOT/src/output"

echo "Building HyperLens software demo..."
CXX="${CXX:-g++-11}"
if ! command -v "$CXX" >/dev/null 2>&1; then
    CXX="g++"
fi

rm -f src/HyperLens
"$CXX" -std=c++17 -fdiagnostics-color=always -g -DHYPERLENS_MAIN \
    src/HyperLens.cpp \
    src/Parallel-Port-Lookup.cpp \
    src/Loader.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp \
    src/GID2_Optimizer.cpp \
    -o src/HyperLens

echo "Running the software demo with src/ACL_rules/test.rules..."
./src/HyperLens src/ACL_rules/test.rules

echo "Generated artifacts:"
for output in \
    final_ip_table_cidr.txt \
    SRC_TCAM_Table.txt \
    SRC_SRAM_Table.txt \
    DST_TCAM_Table.txt \
    DST_SRAM_Table.txt \
    DST_TCAM_Table_Optimized.txt \
    meta_merged.txt; do
    if [[ -f "src/output/$output" ]]; then
        printf '  %s (%s lines)\n' "$output" "$(wc -l < "src/output/$output")"
    fi
done
