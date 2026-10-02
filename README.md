# HyperLens

HyperLens is a research prototype for scalable five-tuple ACL classification on programmable switches. It replaces a large Cartesian lookup with a dependent three-stage pipeline:

```text
packet -> IP + protocol -> GID1 -> source port -> GID2 -> destination port -> action
```

The repository has two layers:

- The default software demo: a C++17 rule compiler that generates IP, TCAM, and SRAM lookup tables.
- The optional Tofino2 integration: a P4 data plane and a Python BF Runtime/PTF control-plane test.

## Quick start: software demo

Requirements:

- Linux
- `g++-11` or a compatible C++17 compiler
- Bash

Build and run the checked-in fixture:

```bash
./build_and_run.sh
```

Run the executable with another rules file:

```bash
./src/HyperLens src/ACL_rules/test.rules
```

The generated tables are written to `src/output/`. They are runtime artifacts and are not committed to the repository.

## ACL rule format

Each rule contains source and destination IP prefixes, source and destination port ranges, a protocol/mask, and an action/mask:

```text
@<source-ip/prefix> <destination-ip/prefix> <source-port-range> <destination-port-range> <protocol/mask> <action/mask>
```

Example:

```text
@10.1.0.0/16 20.0.0.0/8 1000:2000 3000:4000 0x06/0xFF 0x0000/0x0000
```

## Generated tables

The C++ pipeline produces files such as:

- `final_ip_table_cidr.txt`: Stage 1 IP/protocol entries and GID1 values.
- `SRC_TCAM_Table.txt` and `SRC_SRAM_Table.txt`: Stage 2 source-port entries.
- `DST_TCAM_Table.txt` and `DST_SRAM_Table.txt`: Stage 3 destination-port entries.
- `DST_TCAM_Table_Optimized.txt`: optional destination TCAM optimization output.
- `meta_merged.txt` and `src_items.txt`: intermediate metadata for table generation.

## Optional Tofino2 integration

The P4 layer is not required for the software quick start. It requires Intel bf-SDE-9.13.1 and a configured Tofino2 development environment.

Set the SDE variables, then build and install the P4 program:

```bash
export SDE=/opt/bf-sde
export SDE_INSTALL=/opt/bf-sde-install
p4/scripts/build.sh
p4/scripts/install.sh
```

The P4 data plane is in `p4/data_plane/tofino2.p4`. The control-plane test is in `p4/control_plane/Test.py`; it reads generated tables from `src/output/` and requires the BF Runtime/PTF environment supplied by the SDE. Hardware compilation and execution are intentionally separate from the default software demo.

See [the architecture document](docs/architecture.md) for the data-plane/control-plane boundary and table contract.

## Repository layout

```text
HyperLens/
├── README.md
├── LICENSE
├── build_and_run.sh
├── docs/architecture.md
├── p4/
│   ├── data_plane/tofino2.p4
│   ├── control_plane/Test.py
│   └── scripts/{build.sh,install.sh}
└── src/
    ├── *.cpp / *.hpp
    ├── ACL_rules/test.rules
    └── output/                 # generated locally
```

## Authors and citation

Primary contact: Juzhong Wei (`weijzh@pcl.ac.cn`).

If you use HyperLens in academic work, please cite:

```bibtex
@article{huang2026hyperlens,
  author       = {Kun Huang and Juzhong Wei and Rongwei Yang and Xingguo Long and Zhiping Gao and Shaoyong Guo},
  title        = {HyperLens: Scalable High-Speed Packet Classification on Programmable Switches},
  journal      = {Proceedings of the ACM on Networking},
  volume       = {4},
  number       = {CoNEXT4},
  articleno    = {53},
  numpages     = {24},
  month        = dec,
  year         = {2026},
  doi          = {10.1145/3856967}
}
```

## License

HyperLens is released under the Apache License 2.0. See [LICENSE](LICENSE).
