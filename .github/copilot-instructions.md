# HyperLens AI Coding Agent Instructions

AI-optimized guide for understanding and contributing to HyperLens — a high-performance packet classification toolchain for programmable switches.

## Architecture Overview

**Core Innovation:** Three-stage dependent lookup pipeline that reduces memory by 100-1000× compared to traditional Cartesian approaches.

```
[Packet] → [Stage 1: IP+Proto] → GID1 → [Stage 2: SRC Port] → GID2 → [Stage 3: DST Port] → Action
              (ip_table)                    (src_*_table)                 (dst_*_table)
```

**Why dependent lookup?** Traditional ACL implementations expand rules into Cartesian products (one entry per IP×Port combination). HyperLens assigns Group IDs (GIDs) at each stage, creating a dependency chain that eliminates redundancy. Example: 15K rules → 1.4K IP entries + minimal port tables.

### Critical Data Structures

All tables use **hybrid TCAM/SRAM** architecture:
- **TCAM entries**: Sparse port ranges with wildcards (e.g., `00000101110111**`)
- **SRAM entries**: Dense ranges using bitmap representations (quotient/remainder + 32-bit bitmap)

Key metadata flow:
```cpp
Rule5D → split → IPRule + PortRule
                   ↓           ↓
              Merge + intersect → FinalIPRule (with GID1)
                                       ↓
                                  Metainfo_for_SRC_port → BlockMeta_SRC (GID2)
                                                               ↓
                                                          BlockMeta_DST (Action)
```

## Repository Structure

```
P4/tofino2.p4              # P4 data plane (3-stage pipeline with primary/secondary GID paths)
src/
  HyperLens.cpp            # Main entry point, orchestrates 4-step workflow
  Loader.{cpp,hpp}         # ACL rule parsing (format: @IP/prefix IP/prefix proto : port:port port:port action/mask)
  Dependent-Set-Prefix-Lookup.{cpp,hpp}  # IP merging, intersection cell detection, metadata generation
  Parallel-Port-Lookup.{cpp,hpp}         # Port table generation (TCAM/SRAM partitioning)
  ACL_rules/               # Input rulesets (test.rules, acl1/, fw1/, ipc1/, etc.)
  output/                  # Generated tables (final_ip_table_cidr.txt, *_TCAM_Table.txt, *_SRAM_Table.txt)
Test.py                    # Control plane loader (BfRuntimeTest + bfrt_grpc)
target/tofino2/            # Compiled P4 artifacts (bf-rt.json, pipe/, logs/)
```

## Developer Workflows

### 1. Build C++ Toolchain (g++-11)
```bash
# Quick build + run with sample rules
./build_and_run.sh

# Or manual compilation
/usr/bin/g++-11 -std=c++17 -g \
    src/HyperLens.cpp src/Loader.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp src/Parallel-Port-Lookup.cpp \
    -o src/HyperLens

# Run with custom rules
./src/HyperLens src/ACL_rules/acl1/acl1_100k_0.7.rules
```

**Output:** Generates 6 tables in `src/output/`:
- `final_ip_table_cidr.txt` — Stage 1 IP entries with GID1 assignments
- `meta_merged.txt` — GID-to-port-range metadata
- `SRC_{TCAM,SRAM}_Table.txt` — Stage 2 tables
- `DST_{TCAM,SRAM}_Table.txt` — Stage 3 tables with actions

### 2. Build P4 Data Plane (Intel SDE)
```bash
# Requires SDE environment variables
export SDE=/opt/bf-sde
export SDE_INSTALL=/opt/bf-sde-install

./build.sh    # Compiles tofino2.p4 via cmake + p4studio
./install.sh  # Installs to $SDE_INSTALL
```

**What happens:** CMake invokes `$SDE/p4studio/` with flags `-DTOFINO2=ON -DP4_PATH=P4/tofino2.p4`, outputs to `target/tofino2/bf-rt.json`.

### 3. Load Tables to Hardware (Control Plane)
```bash
conda activate controller
./run_controller.sh  # Runs SDE test harness
# OR
python3 Test.py      # Direct PTF test execution
```

**Prerequisites:** Conda env with `ptf`, `bfrt_grpc`, `bfruntime_client_base_tests`.

## Project-Specific Conventions

### P4 Table Naming & Key Structure
- **Stage 1 (IP):** `SwitchIngress.ip_table`
  - Keys: `vrf` (exact), `p.ipv4.{src,dst}` (ternary), `p.ipv4.proto` (exact)
  - Actions: `set_gid1(bit<9> gid1, bit<9> gid_secondary)` — assigns primary + fallback GIDs
- **Stage 2 (SRC Port):** `src_tcam_table`, `src_sram_table` (+ `_secondary` variants)
  - Keys: `ig_md.Group_id` (exact), `p.udp.sport` (ternary) OR `ig_md.src_quotient` (exact for SRAM)
  - Actions: `set_gid2_from_tcam(bit<9> gid2)` or `set_src_bitmap(bit<32> bitmap, bit<9> gid2)`
- **Stage 3 (DST Port):** `dst_tcam_table`, `dst_sram_table`
  - Keys: `ig_md.Group_id2` (exact), `p.udp.dport` (ternary) OR `ig_md.dst_quotient` (exact)
  - Actions: `set_action_from_tcam(bit<9> egress_port)` — final forwarding decision

### Metadata Fields in User-Defined Struct
```p4
struct user_metadata_t {
    bit<9> Group_id;           // GID1 from Stage 1
    bit<9> Group_id_secondary; // Fallback GID1 (for Rmax regions)
    bit<9> Group_id2;          // GID2 from Stage 2
    bit<11> src_quotient;      // High 11 bits of src_port (for SRAM)
    bit<5> src_remainder;      // Low 5 bits of src_port (bitmap index)
    bit<32> src_bitmap;        // Bitmap from SRAM lookup
    bool ip_table_hit;         // Hit flags for control flow
    bool src_tcam_hit, src_sram_hit, dst_tcam_hit, dst_sram_hit;
}
```

### ACL Rule Format
```
@<src_ip>/<prefix> <dst_ip>/<prefix> <src_port_lo>:<src_port_hi> <dst_port_lo>:<dst_port_hi> <proto>/<mask> <action>/<mask>
```
**Example:**
```
@10.1.0.0/16 20.0.0.0/8 1000:2000 3000:4000 0x06/0xFF 0x0000/0x0000  // TCP rule
```

### Intersection Cell Detection
**Key insight:** When multiple IP ranges overlap, their boundaries create "intersection cells" that must be handled separately. These cells receive their own GID1 values (assigned sequentially starting from 0).

**Example from `Dependent-Set-Prefix-Lookup.cpp`:**
```cpp
struct IntersectionCell {
    uint32_t src_lo, src_hi, dst_lo, dst_hi;
    uint8_t proto;
    size_t rmax_id;  // Associated Rmax region (largest covering rule)
    std::vector<size_t> rule_indices;  // Which merged rules overlap this cell
    std::vector<size_t> Extraction;    // Port table indices to query
};
```

## Integration Points

### C++ → P4 Table Generation
1. **C++ outputs** (e.g., `final_ip_table_cidr.txt`):
   ```
   Priority  SrcCIDR        DstCIDR        Proto  GID1,GID_secondary
   1000      10.1.0.0/16    20.0.0.0/8     6      5, 12
   ```
2. **Python control plane** reads files via helper functions (`read_final_ip_table()`)
3. **BfRuntime** inserts via:
   ```python
   key = ip_table.make_key([
       gc_client.KeyTuple('$MATCH_PRIORITY', priority),
       gc_client.KeyTuple('p.ipv4.src', src_ip, src_mask),  # CIDR → IP/mask
       gc_client.KeyTuple('p.ipv4.dst', dst_ip, dst_mask),
       gc_client.KeyTuple('p.ipv4.proto', protocol)
   ])
   data = ip_table.make_data([
       gc_client.DataTuple('gid1', gid1),
       gc_client.DataTuple('gid_secondary', gid_secondary)
   ], 'set_gid1')
   ip_table.entry_add(target, [key], [data])
   ```

### Port Bitmap Encoding
For dense port ranges, use quotient/remainder scheme:
- **Quotient** = `port >> 5` (high 11 bits)
- **Remainder** = `port & 0x1F` (low 5 bits, bitmap index)
- **Bitmap** = 32-bit mask where bit `remainder` = 1 if port is allowed

**Example:** Port 1234 (binary `0000010011010010`)
- Quotient = `0000010011` (38), Remainder = `10010` (18)
- If allowed, set bit 18 in the bitmap for quotient=38

## Common Debugging Scenarios

### Issue: IP Table Entries Explode After CIDR Conversion
**Cause:** Non-aligned IP ranges require multiple CIDR prefixes.
**Fix:** Check `range_to_cidr()` in `Loader.cpp`. Use aligned /24 or /16 blocks when possible.

### Issue: GID Assignment Starts from Wrong Number
**Symptom:** Intersection cells have GIDs > N (where N = number of cells).
**Cause:** Old code assigned merged rule GIDs first. Now fixed: cells get 0-(N-1), merged rules get N+.
**Verify:** Check `laod_and_create_IP_table()` in `Dependent-Set-Prefix-Lookup.cpp`.

### Issue: Test.py Fails with "Table Not Found"
**Cause:** P4 table names mismatch between `tofino2.p4` and `Test.py`.
**Fix:** Ensure table names use `SwitchIngress.` prefix. Cross-reference with `bf-rt.json`.

### Issue: SRAM Bitmap Matches Wrong Ports
**Cause:** Quotient/remainder calculation mismatch between C++ generation and P4 apply block.
**Debug:**
1. Check `tofino2.p4` lines defining `src_quotient` = `p.udp.sport[15:5]`, `src_remainder` = `p.udp.sport[4:0]`
2. Verify C++ `BlockMeta_SRC` uses same bit-slicing in `Parallel-Port-Lookup.cpp`

## Performance Characteristics

| Metric | Traditional | HyperLens | Notes |
|--------|-------------|-----------|-------|
| IP Table Size | 505K entries | 1.4K entries | 357× reduction via merging + intersection cells |
| Total TCAM | ~2M | ~5K | Bitmap SRAM handles dense ranges |
| Memory | ~50 MB | ~150 KB | 99.7% savings |
| Latency | 3 stages | 3 stages | Wire-speed maintained |

**When to use:** Large rulesets (>10K) with high overlap (>50%). Low overlap may not benefit as much.

## Quick Reference Commands

```bash
# Full rebuild + test cycle
./build_and_run.sh && python3 Test.py

# Check generated table sizes
wc -l src/output/*.txt

# Inspect P4 compilation logs
less target/tofino2/logs/tofino2.log

# Debug BfRuntime connection
python3 -c "import bfrt_grpc.client as gc; print('OK')"

# List available conda envs
conda env list | grep controller
```

## VSCode Tasks Available
- `Build: P4Lens (g++-11) - Debug` — Compiles C++ with full debug symbols
- `Build: quick single-file` — Fast compile for single .cpp files

---

**Last Updated:** 2025-12-01  
**Contact:** weijzh@pcl.ac.cn for architecture questions
