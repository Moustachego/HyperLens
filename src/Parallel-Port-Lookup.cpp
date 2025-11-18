/** *************************************************************/
// @Name: Parallel Port Lookup.cpp
// @Function: Handle parallel port lookup for IP rules
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-11-16
/************************************************************* */


#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <set>
#include <algorithm>
#include <fstream>
#include <unordered_map>
#include <limits>
#include <unordered_set>
#include <sstream>
#include <string>
#include <cstdint>
#include <cmath>
#include "input.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"
#include "Parallel-Port-Lookup.hpp"


using namespace std;


//-------------------- Step 1 --------------------
vector<pair<uint16_t,uint16_t>>
step1_collect_intervals(const vector<PortRule>& port_table)
{
    vector<pair<uint16_t,uint16_t>> intervals;
    intervals.reserve(port_table.size());
    for (const auto& p : port_table) {
        intervals.emplace_back(p.src_port_lo, p.src_port_hi);
        cout << "[DBG] Extracted SRC port: " << p.src_port_lo << "-" << p.src_port_hi << endl;
    }
    return intervals;
}

//-------------------- Step 2 --------------------
unordered_map<uint16_t, BlockMeta>
step2_build_block_map(const vector<pair<uint16_t,uint16_t>>& intervals)
{
    const int BLOCK_SIZE = 32;
    unordered_map<uint16_t, BlockMeta> block_map;
    block_map.reserve(intervals.size() * 2);

    for (size_t rid = 0; rid < intervals.size(); ++rid) {
        uint16_t L = intervals[rid].first;
        uint16_t R = intervals[rid].second;
        if (L > R) continue;

        uint16_t bL = L / BLOCK_SIZE;
        uint16_t bR = R / BLOCK_SIZE;

        for (uint16_t b = bL; b <= bR; ++b) {
            uint32_t bm = 0;

            int start = max<int>(L, b * BLOCK_SIZE);
            int end   = min<int>(R, b * BLOCK_SIZE + BLOCK_SIZE - 1);

            for (int p = start; p <= end; ++p)
                bm |= (1U << (p - b * BLOCK_SIZE));

            auto it = block_map.find(b);
            if (it == block_map.end()) {
                block_map[b] = BlockMeta{b, bm, {rid}, false};
            } else {
                it->second.bitmap |= bm;
                it->second.owners.push_back(rid);
            }
        }
    }
    return block_map;
}

//-------------------- Step 3 --------------------
vector<uint16_t>
step3_collect_sorted_block_indices(const unordered_map<uint16_t,BlockMeta>& block_map)
{
    vector<uint16_t> idxs;
    idxs.reserve(block_map.size());
    for (auto& kv : block_map)
        idxs.push_back(kv.first);
    sort(idxs.begin(), idxs.end());
    return idxs;
}

//-------------------- Step 4 --------------------
vector<pair<uint16_t,uint16_t>>
step4_build_runs(const vector<uint16_t>& idxs)
{
    vector<pair<uint16_t,uint16_t>> runs;
    if (idxs.empty()) return runs;

    uint16_t s = idxs[0], prev = idxs[0];
    for (size_t i = 1; i < idxs.size(); ++i) {
        if (idxs[i] == prev + 1)
            prev = idxs[i];
        else {
            runs.emplace_back(s, prev);
            s = prev = idxs[i];
        }
    }
    runs.emplace_back(s, prev);
    return runs;
}

//-------------------- Step 5-A: log2 --------------------
int ilog2_uint16(uint16_t x)
{
    int r = 0;
    while (x > 1) { x >>= 1; ++r; }
    return r;
}

//-------------------- Step 5-B: max initial aligned --------------------
uint16_t max_initial_aligned(uint16_t L, uint16_t R)
{
    uint16_t size = 1;
    while (true) {
        uint16_t next = size << 1;
        if (next == 0) break;
        if ((L % next) == 0 && (uint32_t)(L + next - 1) <= R)
            size = next;
        else
            break;
    }
    return size;
}

//-------------------- Step 6: Build TCAM and SRAM entries with placement strategy --------------------
// Placement strategy: 
//   - Large/dense blocks (>512 ports or high bitmap density) -> SRAM
//   - Small/sparse blocks -> TCAM
// This balances fast lookup (TCAM for common cases) with capacity (SRAM for wide ranges)
pair<vector<SRC_TCAM_Table>, vector<SRC_SRAM_Table>>
step6_build_tcam_and_sram(
    unordered_map<uint16_t,BlockMeta>& block_map,
    const vector<pair<uint16_t,uint16_t>>& runs
){
    const int BLOCK_SIZE = 32;
    const int BLOCK_BITS = 5;

    vector<SRC_TCAM_Table> tcam_out;
    vector<SRC_SRAM_Table> sram_out;

    // full mask for a block of BLOCK_SIZE bits
    const uint32_t FULL_MASK = (BLOCK_SIZE == 32) ? 0xFFFFFFFFu : ((1u << BLOCK_SIZE) - 1u);

    for (auto &r : runs) {
        uint16_t bstart = r.first;
        uint16_t bend = r.second;

        uint16_t b = bstart;
        while (b <= bend) {
            auto it = block_map.find(b);
            if (it == block_map.end() || it->second.assigned) {
                ++b;
                continue;
            }

            // If this block is fully set (all 32 bits), try to form a power-of-two superblock for TCAM
            if (it->second.bitmap == FULL_MASK) {
                // find largest power-of-two cur such that all blocks in [b, b+cur-1] exist, unassigned and full
                uint16_t cur = 1;
                // grow cur while next doubling fits inside bend and blocks are full
                while (true) {
                    uint16_t next = cur << 1;
                    if (next == 0) break; // overflow guard
                    if ((uint32_t)(b + next - 1) > bend) break;
                    bool ok = true;
                    for (uint16_t bb = b + cur; bb <= b + next - 1; ++bb) {
                        auto it2 = block_map.find(bb);
                        if (it2 == block_map.end() || it2->second.assigned || it2->second.bitmap != FULL_MASK) { ok = false; break; }
                    }
                    if (!ok) break;
                    cur = next;
                }

                uint16_t base_port = b * BLOCK_SIZE;
                uint16_t prefix_len = 16 - (BLOCK_BITS + ilog2_uint16(cur));

                // push TCAM entry representing this aligned superblock
                tcam_out.push_back({0, base_port, prefix_len});
                cout << "[TCAM] base_port=" << base_port << " blocks=" << cur << " prefix_len=" << prefix_len << endl;

                for (uint16_t bb = b; bb <= b + cur - 1; ++bb)
                    block_map[bb].assigned = true;

                b += cur;
            } else {
                // Partial block: store its bitmap in SRAM (exact-match bitmap)
                uint16_t base_port = b * BLOCK_SIZE;
                uint32_t bm = it->second.bitmap;
                sram_out.push_back({0, base_port, vector<size_t>{ static_cast<size_t>(bm) }, 0});
                cout << "[SRAM] block=" << b << " base_port=" << base_port << " bitmap=0x" << hex << bm << dec << endl;

                it->second.assigned = true;
                ++b;
            }
        }
    }

    return {tcam_out, sram_out};
}


//-------------------- Step 7: Collect blocks (for debug) --------------------
vector<BlockInfo>
step7_collect_blocks(const unordered_map<uint16_t,BlockMeta>& block_map)
{
    vector<BlockInfo> blocks;
    for (auto &kv : block_map)
        blocks.push_back(BlockInfo{ kv.first, kv.second.bitmap });
    return blocks;
}

// Print detailed block_map for debugging
void step7_print_block_map(const unordered_map<uint16_t,BlockMeta>& block_map) {
    cout << "[BLOCKMAP] total_blocks=" << block_map.size() << "\n";
    for (const auto &kv : block_map) {
        const uint16_t idx = kv.first;
        const BlockMeta &m = kv.second;
        cout << "Block[" << idx << "] bitmap=0x" << hex << m.bitmap << dec
             << " owners={";
        for (size_t i = 0; i < m.owners.size(); ++i) {
            cout << m.owners[i];
            if (i + 1 < m.owners.size()) cout << ",";
        }
        cout << "} assigned=" << (m.assigned ? "yes" : "no") << "\n";
    }
}


//-------------------- Step 8: Print final stats --------------------
void step8_print_stats(
    const unordered_map<uint16_t,BlockMeta>& block_map,
    const vector<SRC_TCAM_Table>& tcam
){
    size_t total = block_map.size();
    size_t assigned = 0;
    for (auto &kv : block_map)
        if (kv.second.assigned) ++assigned;

    cout << "[RESULT] total distinct blocks = " << total
         << ", assigned blocks = " << assigned
         << ", TCAM entries = " << tcam.size() << endl;

    for (size_t i = 0; i < tcam.size(); ++i) {
        cout << "[TCAM][" << i << "] base_port=" << tcam[i].Src_Port_TCAM
             << " prefix_len=" << tcam[i].GroupID2 << endl;
    }
}


//-------------------- Step 9: Main function to build SRC port tables --------------------
pair<pair<vector<BlockInfo>, vector<SRC_TCAM_Table>>, vector<SRC_SRAM_Table>>
create_Table_for_SRC_port(
    const vector<PortRule>& port_table,
    const vector<IPRule>& merged_ip_table
){
    // All intermediate results are declared within function scope
    auto intervals = step1_collect_intervals(port_table);
    auto block_map = step2_build_block_map(intervals);
    // Print block_map for inspection before allocation decisions
    // step7_print_block_map(block_map);
    // Also dump block_map to file for offline inspection
    // {
    //     std::ofstream of("blockmap_dump.txt");
    //     if (of) {
    //         of << "BlockIdx\tBitmapHex\tAssigned\tOwners\n";
    //         for (const auto &kv : block_map) {
    //             of << kv.first << "\t0x" << std::hex << kv.second.bitmap << std::dec
    //                << "\t" << (kv.second.assigned ? "yes" : "no") << "\t";
    //             for (size_t i = 0; i < kv.second.owners.size(); ++i) {
    //                 of << kv.second.owners[i];
    //                 if (i + 1 < kv.second.owners.size()) of << ",";
    //             }
    //             of << "\n";
    //         }
    //         of.close();
    //         cout << "[INFO] blockmap_dump.txt written in current working directory\n";
    //     } else {
    //         cout << "[WARN] cannot open blockmap_dump.txt for writing\n";
    //     }
    // }
    auto idxs = step3_collect_sorted_block_indices(block_map);
    auto runs = step4_build_runs(idxs);

    // Build both SRAM and TCAM tables with placement decision
    auto [src_port_tcam, src_port_sram] = step6_build_tcam_and_sram(block_map, runs);
    auto src_port_blocks = step7_collect_blocks(block_map);

    step8_print_stats(block_map, src_port_tcam);

    // Return blocks, TCAM table, and SRAM table
    return {{src_port_blocks, src_port_tcam}, src_port_sram};
}


void laod_and_create_IP_table(vector<IPRule>& ip_table,
    vector<PortRule>& port_table, 
    vector<IPRule>& merged_ip_table)
{
    // 2) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    cout << "[Main] Merged IP rules = " << merged_ip_table.size() << endl;

    // 3.5) find Rmax for merged_ip_table
    vector<Rmax_IPRule> Rmax_merged_ip_table;
    find_Rmax_for_merged_ip_table(merged_ip_table, Rmax_merged_ip_table);

    // 3) per-protocol elementary intervals (half-open endpoints)
    map<uint8_t, vector<uint32_t>> src_intervals_per_proto;
    map<uint8_t, vector<uint32_t>> dst_intervals_per_proto;
    build_elementary_intervals_per_proto(merged_ip_table,
        src_intervals_per_proto, dst_intervals_per_proto);

    // 4) find intersection cells (per-proto)
    vector<IntersectionCell> intersections;
    vector<size_t> rmax_rule_ids;
    find_intersections_per_proto(merged_ip_table, src_intervals_per_proto, 
        dst_intervals_per_proto, intersections, rmax_rule_ids);

    vector<IPRule> extra_rules;
    extract_and_split_cells(merged_ip_table, intersections, extra_rules);
    cout << "[INFO] Extra rules (range only, no CIDR): " << extra_rules.size() << endl;

    // 7) merge intersection cells + merged IP table into final table
    vector<FinalIPRule> final_ip_table;
    merge_cells_and_ip_table(Rmax_merged_ip_table, intersections, final_ip_table);    

    //8) transfer rule into mask type
    // export final IP table
    Create_Metainfo_for_SRC_port(port_table, merged_ip_table, intersections, final_ip_table);
    write_final_table_in_cidr(final_ip_table, "final_ip_table_cidr.txt");
}

/*************************************************************
 * Step 5: main
 *************************************************************/
int main(int argc, char **argv)  // accept optional path argument
{
    string rules_path = "src/ACL_rules/test.rules";
    if (argc >= 2) rules_path = string(argv[1]);

    vector<Rule5D> rules;
    vector<IPRule> merged_ip_table;
    // attempt to load rules; load_rules_from_file will exit(1) on failure
    load_rules_from_file(rules_path, rules);

    // Optional: show a quick summary so user knows program progressed
    cout << "[Parallel-Port-Lookup] Loaded " << rules.size() << " rules from '" << rules_path << "'\n";

    // Example continuation: split rules and prepare merged ip table (non-mandatory)
    vector<IPRule> ip_table;
    vector<PortRule> port_table;
    split_rules(rules, ip_table, port_table);
    merge_same_ip_entry(ip_table, merged_ip_table);

    laod_and_create_IP_table(ip_table, port_table, merged_ip_table);

    cout << "[Parallel-Port-Lookup] IP entries=" << ip_table.size()
         << ", Port entries=" << port_table.size()
         << ", Merged IP=" << merged_ip_table.size() << "\n";

    // Call the refactored function and capture results
    auto [result, src_port_sram] = create_Table_for_SRC_port(port_table, merged_ip_table);
    auto [src_port_blocks, SRC_TCAM_Table] = result;

    cout << "[Parallel-Port-Lookup] SRC port TCAM table built with " << SRC_TCAM_Table.size() << " entries\n";
    cout << "[Parallel-Port-Lookup] SRC port SRAM table built with " << src_port_sram.size() << " entries\n";
    cout << "[Parallel-Port-Lookup] Block info collected: " << src_port_blocks.size() << " blocks\n";

    return 0;
}
