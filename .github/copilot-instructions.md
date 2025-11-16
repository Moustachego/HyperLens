# Copilot instructions for P4lens

This file gives concise, actionable guidance for an AI coding agent to be productive in this repository.

- Repo layout (key places):
  - `tofino2.p4` (repo root) — main P4 program used by CMake and tests.
  - `src/` — controller/test code and small C++ example (`helloword.cpp`).
  - `ACL_rules/acl_10k.rules` — sample ACL rules file used by the C++ helper.
  - `target/` — CMake build outputs. After a successful build you will find `target/tofino2/` with `bf-rt.json`, `pipe/` and logs.
  - build scripts: `build.sh`, `install.sh`, `run_controller.sh` at repo root.

- Quick contract for edits you might make:
  - Inputs: changes to `tofino2.p4`, `src/*`, or `ACL_rules/*`.
  - Outputs: updated artifacts under `target/`, or tests that run via PTF/BfRuntime.
  - Error modes: missing SDE environment variables, missing conda env `controller`, or absent bfrt/grpc dependencies.

- How to build (explicit):
  1. Ensure SDE variables are set: `SDE` must point to the SDE root and `SDE_INSTALL` to the install prefix.
     Example:
     ```bash
     export SDE=/path/to/sde
     export SDE_INSTALL=/path/to/sde/install
     ./build.sh
     ./install.sh
     ```
  2. What `build.sh` does: it runs `cmake $SDE/p4studio/ -DTOFINO=OFF -DTOFINO2=ON ... -DP4_PATH=${ROOTPATH}/tofino2.p4` and builds the `tofino2` target into `target/`.

- How to run controller/tests (explicit):
  - `run_controller.sh` expects a conda env named `controller`. It does `conda activate controller` then runs `$SDE/run_p4_tests.sh -t <thisdir> --setup` (SDE-provided harness).
  - You can run the Python PTF test directly from repo root after activating the env:
    ```bash
    conda activate controller
    cd /home/long/Desktop/P4lens
    python3 Test.py
    ```
  - `Test.py` uses `BfRuntimeTest` (from `bfruntime_client_base_tests`) and `bfrt_grpc.client`; tests target the P4 program name `tofino2` and manipulate tables like `SwitchIngress.ip_table` and `SwitchIngress.port_table`.

- Important patterns & conventions (project-specific):
  - P4 tables are named with the package + table name: e.g. `SwitchIngress.ip_table`, `SwitchIngress.port_table`.
  - Metadata field `ig_md.Group_id` (bit<9>) is used as a group identifier across tables.
  - The control-plane code inserts entries via `bfrt_info.table_get("SwitchIngress.ip_table")` and uses `gc_client` to build keys/data. Look at `Test.py` for concrete examples.
  - P4 `ip_table` uses ternary matches for `p.ipv4.src`/`p.ipv4.dst` and exact for `p.ipv4.proto`.

- Integration & external dependencies:
  - The SDE (switch development environment) is required and provides `p4studio`, `run_p4_tests.sh`, and toolchain integration used by `build.sh`/`run_controller.sh`.
  - Controller tests expect a conda environment (`controller`) with `ptf`, `bfrt_grpc`, and related packages installed.
  - `bfrt_grpc.client` and `bfruntime_client_base_tests` are used for control-plane interactions.

- Debugging pointers (where to look):
  - After building, inspect `target/tofino2/pipe/` and `target/tofino2/logs/` for generated artifacts and runtime logs.
  - When tests fail, check `Test.py` logging (it configures `logging.basicConfig(level=logging.INFO)`); typical failures are missing entries in `ip_table`/`port_table` or wrong `swports` mapping.
  - C++ helper `src/helloword.cpp` reads `ACL_rules/acl_10k.rules` — useful example of file/layout expectations.

- Small examples (copy-paste safe):
  - Build and install:
    ```bash
    export SDE=/opt/bf-sde
    export SDE_INSTALL=/opt/bf-sde-install
    ./build.sh
    ./install.sh
    ```
  - Run controller tests:
    ```bash
    conda activate controller
    ./run_controller.sh
    ```

- Notes & gaps discovered:
  - `Readme.md` is present but empty; prefer asking a human for missing environment setup details (exact SDE version, required conda packages). If you change README, keep environment instructions consistent with these files.
  - There is no existing `.github/copilot-instructions.md` or AGENT.md — this file should be the canonical short guide for agent use.

If anything here is unclear or you want more detail about a specific area (P4 pipeline, control-plane APIs, or the test harness), tell me which parts to expand and I will update this file.
