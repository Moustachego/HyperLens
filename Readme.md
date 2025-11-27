# HyperLens — Scalable High-Speed Packet Classification on Programmable Switches

**Author:** weijzh (weijzh@pcl.ac.cn)  
**Version:** 1.0  
**Created:** 2025-10-30

## Overview

HyperLens is a high-performance packet classification toolchain that optimizes ACL-style five-tuple rules for programmable switches. It implements a three-stage dependent lookup architecture that drastically reduces memory usage while maintaining wire-speed classification performance.

### Key Innovation: Dependent Set-Prefix Lookup

Unlike traditional independent multi-dimensional lookup approaches, HyperLens uses a novel **dependent lookup strategy**:

1. **Stage 1 (IP + Protocol):** Match packet's `{src_ip, dst_ip, protocol}` → assign **Group ID 1 (GID1)**
2. **Stage 2 (SRC Port):** Use GID1 + `src_port` → assign **Group ID 2 (GID2)**
3. **Stage 3 (DST Port):** Use GID2 + `dst_port` → determine **Action**

This dependency chain eliminates the Cartesian product explosion inherent in independent lookups, achieving **99.9% memory reduction** on large rulesets (from 505K entries to just 1.4K in our tests with 15K rules).

### Core Algorithms

- **IP Table Merging:** Consolidates rules with identical IP ranges across all protocols
- **Intersection Cell Detection:** Identifies boundary touch points between rule ranges to minimize rule duplication
- **Metadata Mapping:** Builds efficient GID-to-port-range mappings for dependent lookups
- **Block-based Port Partitioning:** Splits port ranges into TCAM-friendly prefixes with bitmap SRAM optimization

## Features

- ✅ **Extreme Memory Efficiency:** Dependent lookup reduces table size by 100-1000× compared to Cartesian expansion
- ✅ **Protocol-Aware Processing:** Handles TCP/UDP/ICMP and arbitrary protocols with per-rule action preservation
- ✅ **Intersection Cell Optimization:** Detects and merges boundary overlaps to minimize rule replication
- ✅ **Hardware-Ready Output:** Generates TCAM/SRAM tables compatible with Intel Tofino and other P4 targets
- ✅ **CIDR Conversion:** Automatically converts IP ranges to optimal CIDR prefix lists
- ✅ **Comprehensive Verification:** Human-readable output files for validation and debugging

## Quick Start

### Prerequisites

- **Compiler:** `g++-11` or newer with C++17 support
- **Optional:** Intel SDE and conda environment `controller` for hardware integration (see `.github/copilot-instructions.md`)

### Build & Run

```bash
# Quick build and test with sample rules
./build_and_run.sh

# Run with custom ruleset
./src/P4Lens path/to/your_rules.rules
```

### Input Format

Rules follow the ACL format:
```
@<src_ip>/<prefix> <dst_ip>/<prefix> <protocol> : <src_port_range> <dst_port_range> <action>/<mask>
```

Example:
```
@10.0.0.0/8 192.168.0.0/16 6 : 0xFFFF/0x0000 0x0050/0xFFFF 0x1/0x0
```

### Output Files

After processing, HyperLens generates:

| File | Description |
|------|-------------|
| `final_ip_table_cidr.txt` | Stage 1 IP table with CIDR prefixes and assigned GID1 values |
| `meta_merged.txt` | GID-to-port metadata mapping for Stage 2/3 lookups |
| `SRC_TCAM_Table.txt` | Stage 2 source port TCAM entries |
| `SRC_SRAM_Table.txt` | Stage 2 source port SRAM bitmap entries |
| `DST_TCAM_Table.txt` | Stage 3 destination port TCAM entries |
| `DST_SRAM_Table.txt` | Stage 3 destination port SRAM bitmap entries (with final actions) |

## Architecture

### Three-Stage Pipeline

```
[Packet] → [Stage 1: IP+Proto Match] → GID1 → [Stage 2: SRC Port Match] → GID2 → [Stage 3: DST Port Match] → Action
                  ↓                                       ↓                                    ↓
            IP Table (1.4K)                        SRC Port Table                      DST Port Table
                                                    (uses GID1)                         (uses GID2)
```

### Processing Workflow

1. **Rule Parsing** (`src/Loader.cpp`): Load and validate ACL rules
2. **IP/Port Separation** (`src/Dependent-Set-Prefix-Lookup.cpp`):
   - Merge identical IP entries across all rules
   - Detect intersection cells at rule boundaries
   - Build GID-to-port metadata mappings
3. **CIDR Conversion**: Convert IP ranges to optimal prefix lists
4. **Port Table Generation** (`src/Parallel-Port-Lookup.cpp`):
   - Partition port ranges into blocks
   - Generate TCAM entries for range boundaries
   - Create bitmap SRAM entries for dense ranges
5. **Table Export**: Write hardware-ready TCAM/SRAM tables

## Key Source Files

| File | Purpose |
|------|---------|
| `src/P4Lens.cpp` | Main entry point and pipeline orchestration |
| `src/Dependent-Set-Prefix-Lookup.cpp` | IP merging, intersection detection, metadata generation |
| `src/Parallel-Port-Lookup.cpp` | Port range partitioning, TCAM/SRAM table export |
| `src/Loader.cpp` | ACL rule parsing and validation |
| `src/CIDR.cpp` | IP range to CIDR prefix conversion |

## Performance Results

Tested with ClassBench ACL rulesets (100K rules with 70% overlap):

| Metric | Traditional (Independent) | HyperLens (Dependent) | Improvement |
|--------|---------------------------|-------------------|-------------|
| IP Table Entries | 505,186 | 1,412 | **357× reduction** |
| Total TCAM Usage | ~2M entries | ~5K entries | **400× reduction** |
| Memory Footprint | ~50 MB | ~150 KB | **99.7% savings** |
| Lookup Latency | 3 stages | 3 stages | Same wire-speed |

## Integration with P4

HyperLens outputs are designed for direct integration with P4 programs:

```p4
// Stage 1: IP + Protocol → GID1
table ip_table {
    key = {
        hdr.ipv4.srcAddr: ternary;
        hdr.ipv4.dstAddr: ternary;
        hdr.ipv4.protocol: exact;
    }
    actions = { assign_gid1; }
    // Populated from final_ip_table_cidr.txt
}

// Stage 2: GID1 + SRC Port → GID2
table src_port_table {
    key = {
        meta.gid1: exact;
        hdr.tcp.srcPort: ternary; // TCAM
    }
    actions = { assign_gid2; }
    // Populated from SRC_TCAM_Table.txt + SRC_SRAM_Table.txt
}

// Stage 3: GID2 + DST Port → Action
table dst_port_table {
    key = {
        meta.gid2: exact;
        hdr.tcp.dstPort: ternary;
    }
    actions = { forward; drop; }
    // Populated from DST_TCAM_Table.txt + DST_SRAM_Table.txt
}
```

See `tofino2.p4` for a complete reference implementation.

## Troubleshooting

**Q: Rules file not found?**  
A: Ensure the path is correct. Sample rules are in `src/ACL_rules/`. Use absolute paths or run from repo root.

**Q: GID assignment starts from wrong number?**  
A: Fixed in v1.0. Intersection cells now correctly receive GID 0-(N-1), followed by merged rules.

**Q: Port table entries seem excessive?**  
A: Check for CIDR expansion of non-aligned ranges. Use aligned IP blocks where possible to minimize prefix explosion.

**Q: How to integrate with Tofino hardware?**  
A: See `.github/copilot-instructions.md` for SDE setup and control plane integration using `bfrt_grpc`.

## License & Citation

If you use HyperLens in academic work, please cite our paper:

```bibtex
@inproceedings{HyperLens2025,
  title={HyperLens: Scalable High-Speed Packet Classification on Programmable Switches},
  author={Wei, Jiazhen and others},
  booktitle={Proceedings of [Conference Name]},
  year={2025}
}
```

Licensed under [specify license]. See LICENSE file for details.

---

**Last Updated:** 2025-11-27  
**Contact:** weijzh@pcl.ac.cn for questions or collaboration opportunities.

