**P4Lens — Scalable High-Speed Packet Classification on Programmable Switches**

P4Lens is a compact toolchain for analyzing ACL-style five-tuple rules and producing optimized port-lookup tables suitable for TCAM and SRAM implementation. It implements a full pipeline that: parses ACL rules (including per-rule action fields), splits rules into IP and port dimensions, merges identical IP entries, computes per-port block partitions, and emits TCAM/SRAM table files for both source (SRC) and destination (DST) port lookups.

**Key Features**
- **Protocol-aware rule parsing:** Read rules in the repository ACL format including `ACTION/MASK` field.
- **IP/Port separation & merging:** Merge identical IP entries and build per-port metadata for further processing.
- **Block-based port partitioning:** Split port ranges into prefix-friendly blocks and bitmap-based SRAM entries.
- **Dual pipeline:** Produce both SRC and DST port tables with GroupID bookkeeping and action preservation.
- **Text outputs for verification:** Produces human-readable table files (`SRC_TCAM_Table.txt`, `SRC_SRAM_Table.txt`, `DST_TCAM_Table.txt`, `DST_SRAM_Table.txt`, `final_ip_table_cidr.txt`, `meta_merged.txt`).

**Quick Start (developer)**
- **Prerequisites:**
	- `g++-11` or newer with C++17 support.
	- Optional: SDE and controller conda environment if you intend to integrate with hardware toolchains (see `/.github/copilot-instructions.md`).
- **Build & run (local test rules):**
	- Run the bundled build script which compiles and executes the pipeline:

		```bash
		./build_and_run.sh
		```

	- By default the tool uses `src/ACL_rules/test_port.rules`. To run against a custom rules file, pass its path to the generated binary or to `P4Lens` directly:

		```bash
		./src/P4Lens path/to/your_rules.rules
		```

- **Outputs:** After a successful run you will find (among others):
	- `final_ip_table_cidr.txt` — merged IP table in CIDR format.
	- `meta_merged.txt` — merged metadata used for port processing.
	- `SRC_TCAM_Table.txt`, `SRC_SRAM_Table.txt` — SRC port TCAM/SRAM entries.
	- `DST_TCAM_Table.txt`, `DST_SRAM_Table.txt` — DST port TCAM/SRAM entries (includes action column).

**Development notes**
- Main source files:
	- `src/P4Lens.cpp` — unified main entry point.
	- `src/Parallel-Port-Lookup.cpp` — core port-splitting, block formation, TCAM/SRAM export.
	- `src/Dependent-Set-Prefix-Lookup.cpp` — IP merge and meta generation.
	- `src/input.cpp` / `src/input.hpp` — rule parsing and `Rule5D` structures.
- For reproduction of paper experiments, ensure the rule file format and environment variables described in `/.github/copilot-instructions.md` are set (SDE, SDE_INSTALL, conda env `controller`).

**License & citation**
- If you use P4Lens in academic work or products, please cite the accompanying paper and follow the licensing terms provided with the original repository.

---
Updated to match the paper-style README: concise project overview, features, prerequisites, and quick-start commands.

P4lens:Scalable High-Speed Packet Classification on Programmable Switches

Author: weijzh (weijzh@pcl.ac.cn)
Version: 1.0
Created: 2025-10-30

Project Overview
A high-performance C++ tool for processing IP rules with support for rule merging, interval analysis, and intersection detection. This project implements intelligent processing of IP rule sets to optimize network security policy management and analysis.

