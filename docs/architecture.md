# HyperLens Architecture

HyperLens converts five-tuple ACL rules into a dependent three-stage lookup pipeline for programmable switches.

```text
packet
  -> Stage 1: source/destination IP + protocol
  -> GID1
  -> Stage 2: source port
  -> GID2
  -> Stage 3: destination port
  -> action
```

## Software core

The default demo is a C++17 command-line program. Its processing flow is:

1. `Loader.cpp` parses `src/ACL_rules/test.rules` into five-dimensional rules.
2. The IP and port dimensions are split into `IPRule` and `PortRule` collections.
3. The IP lookup stage merges entries, detects intersections, and assigns GID1 metadata.
4. The port lookup stage emits source and destination TCAM/SRAM tables.
5. `GID2_Optimizer.cpp` optionally compresses the destination TCAM representation.

The software executable writes generated tables to `src/output/`. These files are runtime artifacts and are intentionally ignored by Git.

## Optional P4 integration

The P4 layer is separate from the default software demo and requires Intel bf-SDE. It has two explicit parts:

### Data plane: `p4/data_plane/tofino2.p4`

The Tofino2 program implements the dependent lookup pipeline in the switch ingress. The logical tables are:

- `ip_table`: ternary source/destination IP plus exact protocol, producing GID1 values.
- `src_tcam_table` and `src_sram_table`: source-port lookup producing GID2.
- `src_tcam_table_secondary` and `src_sram_table_secondary`: secondary GID1 fallback path.
- `dst_tcam_table` and `dst_sram_table`: destination-port lookup producing the final action.

Port SRAM entries use a quotient/remainder split: the quotient selects a 32-port bucket and the remainder selects a bitmap bit.

### Control plane: `p4/control_plane/Test.py`

`Test.py` is a BF Runtime/PTF control-plane test. It reads the generated files from the repository's `src/output/` directory and installs the corresponding entries into the Tofino2 tables.

Because BF Runtime, PTF, and Intel SDE are target-specific dependencies, the control plane is not imported or executed by the default C++ quick start.

## Build boundaries

- `build_and_run.sh` builds and runs the software demo with the checked-in `test.rules` fixture.
- `p4/scripts/build.sh` compiles the P4 program through the Intel SDE P4Studio tree.
- `p4/scripts/install.sh` installs the P4 build from `p4/build/`.
- `p4/build/` and generated table files are local artifacts and are not part of the public source snapshot.
