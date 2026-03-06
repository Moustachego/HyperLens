# HyperLens AI Coding Agent Instructions

High-performance packet classification toolchain for programmable switches. Three-stage dependent lookup pipeline reduces TCAM by 100–1000× vs. traditional Cartesian approaches.

## Architecture

```
[Packet] → [Stage 1: IP+Proto] → GID1 → [Stage 2: SRC Port] → GID2 → [Stage 3: DST Port] → Action
              (ip_table)                   (src_*_table)                  (dst_*_table)
```

**Why:** Traditional ACL expands rules into IP×Port Cartesian products. HyperLens assigns Group IDs (GIDs) at each stage, creating a dependency chain that eliminates redundancy (e.g., 15K rules → 1.4K IP entries + minimal port tables).

## 4-Step C++ Pipeline (`HyperLens.cpp`)

1. **`load_rules_from_file()`** (`Loader.cpp`) — Parse `@srcIP/pfx dstIP/pfx srcPorts dstPorts proto/mask action/mask`
2. **`split_rules()`** (`Loader.cpp`) — Separate `Rule5D` → `vector<IPRule>` + `vector<PortRule>`
3. **`load_and_create_IP_table()`** (**`Parallel-Port-Lookup.cpp`**, not Dependent-Set) — Merge identical IPs, detect intersection cells, assign GID1. Internally: `merge_same_ip_entry()` → `find_Rmax` → `find_intersections_per_proto()` → `Reorder_merged_ip_table()` → `Create_Metainfo_for_port()`
4. **`create_Table_for_port()`** (`Parallel-Port-Lookup.cpp`) — Port ranges → quotient/remainder TCAM/SRAM blocks → output files

**Default rules:** `src/ACL_rules/fw1/fw1_50k_16_0.5.rules` (override via `argv[1]`)

## Build & Run

```bash
./build_and_run.sh                    # Clean + compile (g++-11 C++17) + run with default rules
./src/HyperLens path/to/rules.rules  # Run with custom rules

# GID2 optimizer (standalone, separate compilation):
g++-11 -std=c++17 src/GID2_Optimizer.cpp -o src/GID2_Optimizer
./src/GID2_Optimizer                  # DST_TCAM_Table.txt → DST_TCAM_Table_Optimized.txt
```

**VS Code task:** `Build: HyperLens (g++-11) - Debug` → `src/HyperLens.debug` with `-O0 -Wall -Wextra`.

**Compilation units:** Always link 4 files together: `HyperLens.cpp`, `Loader.cpp`, `Dependent-Set-Prefix-Lookup.cpp`, `Parallel-Port-Lookup.cpp`. `GID2_Optimizer.cpp` is standalone.

## Key Data Structures

| Struct | Header | Role |
|--------|--------|------|
| `Rule5D` | `Loader.hpp` | 5-tuple with ranges, prefix lengths, action string |
| `IPRule` | `Loader.hpp` | IP dims + `merged_R` (rule indices) + `rmax_id` |
| `PortRule` | `Loader.hpp` | Port dims + action string (e.g., `"0x0000/0x0200"`) |
| `IntersectionCell` | `Dependent-Set-Prefix-Lookup.hpp` | Overlapping IP region; has `minimal`, `cover_set`, `Extraction` |
| `FinalIPRule` | `Dependent-Set-Prefix-Lookup.hpp` | Output with `group_ids`, `is_cell`, `is_rmax` flags |
| `MergedItem` | `Dependent-Set-Prefix-Lookup.hpp` | GID → port-range metadata |
| `BlockMeta_SRC/DST` | `Parallel-Port-Lookup.hpp` | Port block + bitmap + TCAM/SRAM assignment |
| `DST_Port_Type` | `Parallel-Port-Lookup.hpp` | Enum: POINT, SHORT_RANGE, LONG_RANGE, WILDCARD |

## P4 Data Plane (`P4/tofino2.p4`) — 7 Tables

| Table | Stage | Keys |
|-------|-------|------|
| `ip_table` | 1 (IP) | vrf(exact), src/dst IP(ternary), proto(exact) → `set_gid1(gid1, gid_secondary)` |
| `src_tcam_table` | 2 (SRC primary) | Group_id(exact), sport(ternary) → `set_gid2_from_tcam(gid2)` |
| `src_sram_table` | 2 (SRC primary) | Group_id(exact), src_quotient(exact) → bitmap + gid2 |
| `src_tcam_table_secondary` | 2 (SRC fallback) | Group_id_secondary path |
| `src_sram_table_secondary` | 2 (SRC fallback) | Group_id_secondary path |
| `dst_tcam_table` | 3 (DST) | Group_id2(exact), dport(ternary) → action |
| `dst_sram_table` | 3 (DST) | Group_id2(exact), dst_quotient(exact) → bitmap + action |

**Quotient/Remainder:** `port >> 5` = quotient (SRAM index), `port & 0x1F` = remainder (bitmap bit).

## Python Tools

| Script | Purpose |
|--------|---------|
| `Test.py` | Control plane: loads tables to Tofino2 via BfRuntime gRPC (`conda activate controller`) |
| `Self-inspection.py` | End-to-end verification: test packets → IP → SRC/DST TCAM/SRAM → Action. Uses `FailStage` enum (IP/SRC_TCAM/SRC_SRAM/DST_TCAM/DST_SRAM/ACTION) |
| `generate_test_dataset.py` | Generates ~10 test packets per rule (IPs varied within mask, ports random) |
| `clean_acl_rules.py` | Deduplicates rules with identical 5-tuple |

## Output Files (`src/output/`)

| File | Producer | Consumer |
|------|----------|----------|
| `final_ip_table_cidr.txt` | HyperLens C++ | `Test.py`, `Self-inspection.py` |
| `SRC/DST_TCAM_Table.txt`, `SRC/DST_SRAM_Table.txt` | HyperLens C++ | `Test.py`, `Self-inspection.py` |
| `DST_TCAM_Table_Optimized.txt` | `GID2_Optimizer` | Post-processing output |
| `meta_merged.txt`, `src_items.txt` | HyperLens C++ | Internal metadata |
| `*_testset.txt` | `generate_test_dataset.py` | `Self-inspection.py` |
| `intersection_analysis.json` | HyperLens C++ | Debug/analysis |

## Conventions

- **C++17** with `g++-11`. Comments: file headers in English, inline comments mostly Chinese. `★` marks important changes.
- **Naming:** Functions/variables use `snake_case`, some legacy `CamelCase` (`Group_id`, `Create_Metainfo_for_port`).
- **Actions** stored as raw strings (`"0x0000/0x0200"`), never parsed to int.
- **Known intentional typos — do NOT "fix":** `mateinfo` (should be `metainfo`) in `HyperLens.cpp`; comment `laod_and_create_IP_table` in `HyperLens.cpp` (function itself is correctly named `load_and_create_IP_table`).
- **P4 prerequisites:** Intel bf-SDE-9.13.1, `$SDE=/opt/bf-sde`, `$SDE_INSTALL=/opt/bf-sde-install`. Only needed when modifying `P4/tofino2.p4`.
- **Contact:** weijzh@pcl.ac.cn
