/** *************************************************************/
// @Name: Parallel Port Lookup.cpp
// @Function: Handle parallel port lookup for IP rules
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-11-16
/************************************************************* */

#include "input.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"
#include "Parallel-Port-Lookup.hpp"
#include <vector>
#include <utility>  // for std::pair
#include <iostream>
#include <cmath>
#include <unordered_map>
#include <algorithm>
#include <cstdint>

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

//-------------------- Step 6: Build TCAM entries --------------------
vector<SRC_TCAM_Table>
step6_build_tcam(
    unordered_map<uint16_t,BlockMeta>& block_map,
    const vector<pair<uint16_t,uint16_t>>& runs
){
    const int BLOCK_SIZE = 32;
    const int BLOCK_BITS = 5;

    vector<SRC_TCAM_Table> out;

    for (auto &r : runs) {
        uint16_t L = r.first;
        uint16_t R = r.second;

        while (L <= R) {
            uint16_t size = max_initial_aligned(L, R);

            uint16_t cur = size;
            bool ok_found = false;

            while (cur >= 1) {
                bool ok = true;
                for (uint16_t b = L; b <= L + cur - 1; ++b) {
                    auto it = block_map.find(b);
                    if (it == block_map.end() || it->second.assigned) {
                        ok = false; break;
                    }
                }
                if (ok) { ok_found = true; break; }
                cur >>= 1;
            }

            if (!ok_found) {
                ++L;
                continue;
            }

            uint16_t base_port = L * BLOCK_SIZE;
            uint16_t prefix_len = 16 - (BLOCK_BITS + ilog2_uint16(cur));

            out.push_back({
                0,
                base_port,
                prefix_len
            });

            for (uint16_t b = L; b <= L + cur - 1; ++b)
                block_map[b].assigned = true;

            L += cur;
        }
    }
    return out;
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
pair<vector<BlockInfo>, vector<SRC_TCAM_Table>>
create_Table_for_SRC_port(
    const vector<PortRule>& port_table,
    const vector<IPRule>& merged_ip_table
){
    // All intermediate results are declared within function scope
    auto intervals = step1_collect_intervals(port_table);
    auto block_map = step2_build_block_map(intervals);
    auto idxs = step3_collect_sorted_block_indices(block_map);
    auto runs = step4_build_runs(idxs);

    auto src_port_tcam = step6_build_tcam(block_map, runs);
    auto src_port_blocks = step7_collect_blocks(block_map);

    step8_print_stats(block_map, src_port_tcam);

    // Return both results as a pair
    return {src_port_blocks, src_port_tcam};
}


/*************************************************************
 * Step 5: main
 *************************************************************/
int main(int argc, char **argv)  // accept optional path argument
{
    string rules_path = "ACL_rules/test.rules";
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

    cout << "[Parallel-Port-Lookup] IP entries=" << ip_table.size()
         << ", Port entries=" << port_table.size()
         << ", Merged IP=" << merged_ip_table.size() << "\n";

    // Call the refactored function and capture results as a pair
    auto [src_port_blocks, SRC_TCAM_Table] = create_Table_for_SRC_port(port_table, merged_ip_table);

    cout << "[Parallel-Port-Lookup] SRC port TCAM table built with " << SRC_TCAM_Table.size() << " entries\n";
    cout << "[Parallel-Port-Lookup] Block info collected: " << src_port_blocks.size() << " blocks\n";

    return 0;
}
