/** *************************************************************/
// @Name: Dependent_set.cpp
// @Function: Handle merging of IP rules and mapping to Group_IDs
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-10-30
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

using namespace std;


/********************************************************************
 * Name: merge_same_ip_entry (only keep merged_R version)
 * Function:
 *   - 合并 IP 规则中“完全一样”的项
 *   - 每条合并后的 IPRule 里记录 merged_R = {原始规则编号...}
 *   - 重新设置合并后规则的 priority（按出现顺序 1,2,3,...）
 ********************************************************************/
void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<IPRule>& merged_ip_table
) {
    merged_ip_table.clear();

    std::map<
        std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint8_t>,
        size_t
    > key_to_index;

    for (size_t i = 0; i < ip_table.size(); ++i) {
        const auto &rule = ip_table[i];
        auto key = std::make_tuple(
            rule.src_ip_lo, rule.src_ip_hi,
            rule.dst_ip_lo, rule.dst_ip_hi,
            rule.proto
        );

        auto it = key_to_index.find(key);
        if (it == key_to_index.end()) {
            IPRule new_rule = rule;
            new_rule.merged_R.clear();
            new_rule.merged_R.push_back(i);  // 记录原始规则编号

            merged_ip_table.push_back(new_rule);
            key_to_index[key] = merged_ip_table.size() - 1;
        } else {
            size_t idx = it->second;
            merged_ip_table[idx].merged_R.push_back(i);
        }
    }

    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        merged_ip_table[i].priority = static_cast<uint32_t>(i + 1);
    }

    std::cout << "[merge_same_ip_entry] Original IP rules = " << ip_table.size()
              << ", merged = " << merged_ip_table.size() << std::endl;
}



/*************************************************************
 * Name: build_elementary_intervals_per_proto
 * Fuction: build elementary intervals per protocol for src and dst IPs
 * @ input: merged ip_table
 * @ output: src_intervals_per_proto, dst_intervals_per_proto
 *************************************************************/
void build_elementary_intervals_per_proto(
    const vector<IPRule>& ip_table,
    map<uint8_t, vector<uint32_t>>& src_intervals_per_proto,
    map<uint8_t, vector<uint32_t>>& dst_intervals_per_proto)
{
    src_intervals_per_proto.clear();
    dst_intervals_per_proto.clear();

    // per-proto sets to collect endpoints (set keeps order)
    map<uint8_t, set<uint32_t>> src_set_per_proto;
    map<uint8_t, set<uint32_t>> dst_set_per_proto;

    for (const auto& rule : ip_table) {
        src_set_per_proto[rule.proto].insert(rule.src_ip_lo);
        src_set_per_proto[rule.proto].insert(rule.src_ip_hi);
        dst_set_per_proto[rule.proto].insert(rule.dst_ip_lo);
        dst_set_per_proto[rule.proto].insert(rule.dst_ip_hi);
    }

    // convert sets to vectors (ordered)
    for (const auto& kv : src_set_per_proto) {
        uint8_t proto = kv.first;
        const auto &sset = kv.second;
        // copy sorted endpoints into vector
        src_intervals_per_proto[proto].assign(sset.begin(), sset.end());
        // dst: may be empty if no entry in dst_set_per_proto for this proto
        const auto &dset = dst_set_per_proto[proto]; // operator[] yields empty set if absent
        dst_intervals_per_proto[proto].assign(dset.begin(), dset.end());

        cout << "[build_elementary_intervals] Proto=" << (int)proto
             << " Src intervals=" << src_intervals_per_proto[proto].size()
             << " Dst intervals=" << dst_intervals_per_proto[proto].size() << endl;
    }
}

/*************************************************************
 * Name: covers
 * Fucttion: check if prefix A covers prefix B
 * @ input: Rule A, Rule B
 * @ output: 0/1
 *************************************************************/
static inline bool covers(const IPRule& A, const IPRule& B) {
    if (&A == &B) return false; // 显式排除自己（按引用比较）
    return (A.src_ip_lo <= B.src_ip_lo &&
            A.src_ip_hi >= B.src_ip_hi &&
            A.dst_ip_lo <= B.dst_ip_lo &&
            A.dst_ip_hi >= B.dst_ip_hi);
}

/*************************************************************
 * Name: find_best_cover_rule_in_set
 * Fucttion: find iterative R0-driven partition,table A(reamining) 
 * compared to table B(ip table)
 * @ input: merged ip_table, reamining_rules(a kv table including reamining rules)
 * @ output: R0 position in rule_indices
 *************************************************************/
static inline size_t find_best_cover_rule_in_set(
    const vector<IPRule>& ip_table,
    const vector<size_t>& reamining_rules)
{
    size_t best_pos = 0;
    size_t best_count = 0;
    for (size_t p = 0; p < reamining_rules.size(); ++p) {
        size_t ridA = reamining_rules[p];
        const auto &A = ip_table[ridA];
        size_t cnt = 0;
        for (size_t q = 0; q < reamining_rules.size(); ++q) {
            size_t ridB = reamining_rules[q];
            if (covers(A, ip_table[ridB])) ++cnt;
        }
        if (cnt > best_count) {
            best_count = cnt;
            best_pos = p;
        }
        if (cnt == reamining_rules.size()) {
            return p;
        }
    }
    return best_pos;
}

/*************************************************************
 * Name: make_cell_key
 * Fucttion: make a string key for a cell for deduplication
 * @ input: cell parameters
 * @ output: string key
 *************************************************************/
static inline string make_cell_key(uint8_t proto,
                                   uint32_t s_lo, uint32_t s_hi,
                                   uint32_t d_lo, uint32_t d_hi) {
    // compact string key for dedupe
    std::ostringstream oss;
    oss << (int)proto << ":" << s_lo << "-" << s_hi << ":" << d_lo << "-" << d_hi;
    return oss.str();
}

/*************************************************************
 * Name: collect_line_and_point_cells
 * Fucttion: Judge whether the cells of R1 and R2 have a 
 * line-and-point intersection.  
 * @ input: ip_table, proto_rules, proto
 * @ output: local_cells, seen_keys
 *************************************************************/
void collect_line_and_point_cells(
    const vector<IPRule>& ip_table,
    const vector<size_t>& proto_rules,
    uint8_t proto,
    vector<IntersectionCell>& local_cells,
    unordered_set<string>& seen_keys,
    size_t rmax_id
 )
{

    size_t n = proto_rules.size();

    vector<pair<uint32_t,string>> src_points;

    for (size_t ia = 0; ia < n; ++ia) {
        const IPRule &A = ip_table[ proto_rules[ia] ];
        for (size_t ib = ia + 1; ib < n; ++ib) {
            const IPRule &B = ip_table[ proto_rules[ib] ];

            // --- 1) src boundary touch cases ---
            // A.src_hi == B.src_lo  or B.src_hi == A.src_lo


            if (A.src_ip_hi == B.src_ip_lo || B.src_ip_hi == A.src_ip_lo) {
            uint32_t px = (A.src_ip_hi == B.src_ip_lo) ? A.src_ip_hi : B.src_ip_hi; // the touching point
            // compute dst overlap (closed interval) between A and B
            uint32_t dlo = std::max(A.dst_ip_lo, B.dst_ip_lo);
            uint32_t dhi = std::min(A.dst_ip_hi, B.dst_ip_hi);
            if (dhi >= dlo) { 
                vector<size_t> covered;
                for (size_t rid : proto_rules) {
                    const auto &R = ip_table[rid];
                    if ((R.src_ip_lo <= px && px <= R.src_ip_hi) &&
                        (R.dst_ip_lo <= dlo && dhi <= R.dst_ip_hi)) {
                        covered.push_back(rid);
                    }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, px, px, dlo, dhi);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({px, px, dlo, dhi, proto, rmax_id, covered});
                    }
                }
            }
            }
            
            // --- 2) dst boundary touch cases ---
            if (A.dst_ip_hi == B.dst_ip_lo || B.dst_ip_hi == A.dst_ip_lo) {
            uint32_t py = (A.dst_ip_hi == B.dst_ip_lo) ? A.dst_ip_hi : B.dst_ip_hi;
            uint32_t slo = std::max(A.src_ip_lo, B.src_ip_lo);
            uint32_t shi = std::min(A.src_ip_hi, B.src_ip_hi);
                if (shi >= slo) { // overlap length >= 1 -> line along dst point py
                    vector<size_t> covered;
                    for (size_t rid : proto_rules) {
                        const auto &R = ip_table[rid];
                        if ((R.src_ip_lo <= slo && shi <= R.src_ip_hi) &&
                            (R.dst_ip_lo <= py && py <= R.dst_ip_hi)) {
                            covered.push_back(rid);
                        }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, slo, shi, py, py);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({slo, shi, py, py, proto, rmax_id, covered});
                    }
                }
            }
            }
             
            // --- 3) point touch (both src & dst touching) ---
            bool src_touch_ab = (A.src_ip_hi == B.src_ip_lo);
            bool src_touch_ba = (B.src_ip_hi == A.src_ip_lo);
            bool dst_touch_ab = (A.dst_ip_hi == B.dst_ip_lo);
            bool dst_touch_ba = (B.dst_ip_hi == A.dst_ip_lo);
            // four combos:
            if (src_touch_ab && dst_touch_ab) {
                uint32_t px = A.src_ip_hi, py = A.dst_ip_hi;
                // check containment among proto rules
                vector<size_t> covered;
                covered.reserve(8);
                for (size_t rid : proto_rules) {
                    const auto &R = ip_table[rid];
                    if ((R.src_ip_lo <= px && px <= R.src_ip_hi) &&
                        (R.dst_ip_lo <= py && py <= R.dst_ip_hi)) {
                        covered.push_back(rid);
                    }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, px, px, py, py);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered});
                    }
                }
            }
            if (src_touch_ab && dst_touch_ba) {
                uint32_t px = A.src_ip_hi, py = B.dst_ip_hi;
                vector<size_t> covered;
                for (size_t rid : proto_rules) {
                    const auto &R = ip_table[rid];
                    if ((R.src_ip_lo <= px && px <= R.src_ip_hi) &&
                        (R.dst_ip_lo <= py && py <= R.dst_ip_hi)) {
                        covered.push_back(rid);
                    }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, px, px, py, py);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered});
                    }
                }
            }
            if (src_touch_ba && dst_touch_ab) {
                uint32_t px = B.src_ip_hi, py = A.dst_ip_hi;
                vector<size_t> covered;
                for (size_t rid : proto_rules) {
                    const auto &R = ip_table[rid];
                    if ((R.src_ip_lo <= px && px <= R.src_ip_hi) &&
                        (R.dst_ip_lo <= py && py <= R.dst_ip_hi)) {
                        covered.push_back(rid);
                    }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, px, px, py, py);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered});
                    }
                }
            }
            if (src_touch_ba && dst_touch_ba) {
                uint32_t px = B.src_ip_hi, py = B.dst_ip_hi;
                vector<size_t> covered;
                for (size_t rid : proto_rules) {
                    const auto &R = ip_table[rid];
                    if ((R.src_ip_lo <= px && px <= R.src_ip_hi) &&
                        (R.dst_ip_lo <= py && py <= R.dst_ip_hi)) {
                        covered.push_back(rid);
                    }
                }
                if (covered.size() >= 2) {
                    string key = make_cell_key(proto, px, px, py, py);
                    if (seen_keys.insert(key).second) {
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered});
                    }
                }
            }
        } // ib
    } // ia
}

// -------------------------------------------------------
// Build ancestors: 对 remaining 中的每条规则，构建其"祖先规则集合"
// ancestors[r] = 所有能直接或间接 covers(r) 的规则列表
// -------------------------------------------------------
static void build_ancestors(
    const vector<size_t>& remaining,
    const vector<IPRule>& merged_ip_table,
    unordered_map<size_t, vector<size_t>>& ancestors,
    size_t rmax_id
)
{
    vector<size_t> rem = remaining;
    // -------------------------------------
    // Step 0: 把 Rmax 移除（关键！你之前漏掉的）
    // -------------------------------------
    rem.erase(std::remove(rem.begin(), rem.end(), rmax_id), rem.end());

    ancestors.clear();
    for (size_t rid : rem) {
        ancestors[rid] = vector<size_t>();
    }

    // Step 1: 直接父
    for (size_t a : rem) {
        for (size_t b : rem) {
            if (a == b) continue;
            if (covers(merged_ip_table[a], merged_ip_table[b])) {
                ancestors[b].push_back(a);
            }
        }
    }

    // Step 2: 传递闭包
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& kv : ancestors) {
            size_t node = kv.first;
            auto& vec = kv.second;

            vector<size_t> to_add;
            for (size_t p : vec) {
                auto itp = ancestors.find(p);
                if (itp == ancestors.end()) continue;
                for (size_t gp : itp->second) {
                    if (gp == node) continue;
                    if (find(vec.begin(), vec.end(), gp) == vec.end()) {
                        to_add.push_back(gp);
                    }
                }
            }
            if (!to_add.empty()) {
                for (size_t x : to_add) vec.push_back(x);
                changed = true;
            }
        }
    }
}

// -------------------------------------------------------
// 判定一个 cell 是否无效
// 输入:
//   covered = 所有覆盖该 cell 的规则 ID 列表
//   ancestors = 每条规则的祖先列表（由 build_ancestors 构建）
//   merged_ip_table = 规则表，用于 covers 判定
// 返回:
//   true = cell 应过滤掉
// -------------------------------------------------------
static bool cell_is_invalid(
    const vector<size_t>& covered,
    const unordered_map<size_t, vector<size_t>>& ancestors,
    const vector<IPRule>& merged_ip_table)
{
    if (covered.size() < 2) return true;

    // ----------------- Step 1: 祖先冗余判定 -----------------
    auto redundant_via_ancestors = [&](const vector<size_t>& cov)->bool {
        for (size_t r : cov) {

            auto it = ancestors.find(r);
            if (it == ancestors.end()) continue;
            const vector<size_t>& anc = it->second;

            if (1 + anc.size() < cov.size()) continue;

            bool all_in = true;
            for (size_t x : cov) {
                if (x == r) continue;
                if (find(anc.begin(), anc.end(), x) == anc.end()) {
                    all_in = false;
                    break;
                }
            }
            if (all_in) return true;
        }
        return false;
    };

    if (redundant_via_ancestors(covered)) {
        return true;
    }

    // ----------------- Step 2: 正确 minimal 判定 -----------------
    vector<size_t> minimal;
    minimal.reserve(covered.size());

    auto strictly_covers = [&](const IPRule& big, const IPRule& small) {
        return (big.src_ip_lo <= small.src_ip_lo &&
                big.src_ip_hi >= small.src_ip_hi &&
                big.dst_ip_lo <= small.dst_ip_lo &&
                big.dst_ip_hi >= small.dst_ip_hi);
    };

    auto strictly_smaller = [&](const IPRule& a, const IPRule& b) {
        return strictly_covers(b, a) && !strictly_covers(a, b);
    };

    for (size_t r : covered) {
        bool dominated = false;

        for (size_t s : covered) {
            if (r == s) continue;

            // 只有更小的规则才可以支配更大的规则
            if (strictly_smaller(merged_ip_table[s], merged_ip_table[r])) {
                dominated = true;
                break;
            }
        }

        if (!dominated) {
            minimal.push_back(r);  // r 是 minimal
        }
    }

    // ----------------- 判断是否可用 -----------------
    return (minimal.size() < 2);
}


/*************************************************************
 * Name: find_intersections_per_proto
 * Fucttion: find intersection cells per protocol
 * @ input: ip table
 * @ output: src_intervals_per_proto, dst_intervals_per_proto
 *************************************************************/
void find_intersections_per_proto(
    const vector<IPRule>& merged_ip_table,
    const map<uint8_t, vector<uint32_t>>& src_intervals_per_proto,
    const map<uint8_t, vector<uint32_t>>& dst_intervals_per_proto,
    vector<IntersectionCell>& intersections,
    vector<size_t>& rmax_rule_ids)   // global container (will be appended)
{
    size_t global_before = intersections.size();

    // 1) bucket rules by proto: map proto -> indices (indices correspond to ip_table)
    map<uint8_t, vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        proto_to_rule_indices[merged_ip_table[i].proto].push_back(i);
    }

    // 2) process each proto separately
    for (const auto& kv : proto_to_rule_indices) {
        uint8_t proto = kv.first;
        vector<size_t> remaining = kv.second; // remaining rules for this proto

        auto it_src = src_intervals_per_proto.find(proto);
        auto it_dst = dst_intervals_per_proto.find(proto);
        if (it_src == src_intervals_per_proto.end() || it_dst == dst_intervals_per_proto.end()) {
            cout << "[find_intersections] Proto=" << (int)proto << " no intervals found\n";
            continue;
        }
        const auto& src_ep = it_src->second;
        const auto& dst_ep = it_dst->second;

        cout << "[find_intersections] Proto=" << (int)proto
             << " start total_rules=" << remaining.size()
             << " endpoints src=" << src_ep.size() << " dst=" << dst_ep.size() << endl;

        if (remaining.size() < 2) {
            cout << "[find_intersections] Proto=" << (int)proto << " not enough rules, skip\n";
            continue;
        }

        // local accumulator for this proto
        vector<IntersectionCell> local_cells;
        unordered_set<string> seen_keys;
        cout << "[find_intersections] Proto=" << (int)proto 
            << " line/point cells collected = " << local_cells.size() << endl;
      
        // Iteratively peel off subsets dominated by a best-cover rule (R0)
        while (remaining.size() >= 2) {
            size_t best_pos = find_best_cover_rule_in_set(merged_ip_table, remaining);
            size_t best_rid = remaining[best_pos];
            const auto &Rmax = merged_ip_table[best_rid];
            rmax_rule_ids.push_back(best_rid);

            unordered_map<size_t, vector<size_t>> ancestors;        
            build_ancestors(remaining, merged_ip_table, ancestors, best_rid);
            collect_line_and_point_cells(merged_ip_table, remaining, proto, local_cells, seen_keys, best_rid);  

            vector<size_t> S;
            S.reserve(remaining.size());
            for (size_t rid : remaining) {

                if (covers(Rmax, merged_ip_table[rid])) 
                    S.push_back(rid);   //this cover confuzes me
            }
            
            // If S size < 2, that means Rmax doesn't cover more than itself effectively:
            // in this case we should still try to handle at least pairwise among remaining:
            if (S.size() < 2) {
                remaining.erase(remaining.begin() + best_pos);
                // to ensure we still try to find intersections among rest later, continue.
                continue;
            }

            size_t src_start_idx = 0;
            while (src_start_idx < src_ep.size() && src_ep[src_start_idx] < Rmax.src_ip_lo) ++src_start_idx;
            size_t src_end_idx = src_start_idx;
            while (src_end_idx < src_ep.size() && src_ep[src_end_idx] <= Rmax.src_ip_hi) ++src_end_idx;
            // src_ep indices to iterate: [src_start_idx, src_end_idx - 1] as cell starts (must have +1)
            if (src_end_idx <= src_start_idx + 0) {
                // no endpoints inside Rmax - fallback: expand to nearest endpoints
                src_start_idx = 0; src_end_idx = 0; // will skip cell loop
            }

            size_t dst_start_idx = 0;
            while (dst_start_idx < dst_ep.size() && dst_ep[dst_start_idx] < Rmax.dst_ip_lo) ++dst_start_idx;
            size_t dst_end_idx = dst_start_idx;
            while (dst_end_idx < dst_ep.size() && dst_ep[dst_end_idx] <= Rmax.dst_ip_hi) ++dst_end_idx;
            if (dst_end_idx <= dst_start_idx + 0) {
                dst_start_idx = 0; dst_end_idx = 0;
            }

            // Enumerate elementary cells **restricted to Rmax** using endpoints (treat endpoints as half-open)
            for (size_t si = src_start_idx; si + 1 < src_ep.size() && si + 1 <= src_end_idx; ++si) {
                // ensure the interval [src_ep[si], src_ep[si+1]-1] lies inside Rmax
                uint32_t cell_src_lo = src_ep[si];
                uint32_t next_src = src_ep[si+1];
                uint32_t cell_src_hi = (next_src == 0 ? numeric_limits<uint32_t>::max() : next_src );
                if (cell_src_lo < Rmax.src_ip_lo || cell_src_hi > Rmax.src_ip_hi) {
                    // if not entirely inside Rmax, skip
                    continue;
                }
                if (cell_src_hi < cell_src_lo) continue;

                for (size_t dj = dst_start_idx; dj + 1 < dst_ep.size() && dj + 1 <= dst_end_idx; ++dj) {
                    uint32_t cell_dst_lo = dst_ep[dj];
                    uint32_t next_dst = dst_ep[dj+1];
                    uint32_t cell_dst_hi = (next_dst == 0 ? numeric_limits<uint32_t>::max() : next_dst );
                    if (cell_dst_lo < Rmax.dst_ip_lo || cell_dst_hi > Rmax.dst_ip_hi) {
                        continue;
                    }
                    if (cell_dst_hi < cell_dst_lo) continue;

                    // collect which rules in S cover this cell (use your specified containment test)
                    // cout << "Cell: " << cell_src_lo << "-" << cell_src_hi 
                    // << " , " << cell_dst_lo << "-" << cell_dst_hi
                    // << "   [src_ep idx = " << si << ", dst_ep idx = " << dj << "]"  
                    // << endl;
                    vector<size_t> covered;
                    covered.reserve(8);
                    for (size_t rid : S) {
                        const auto& rule = merged_ip_table[rid];
                        if ((rule.src_ip_lo <= cell_src_lo && cell_src_hi <= rule.src_ip_hi) &&
                            (rule.dst_ip_lo <= cell_dst_lo && cell_dst_hi <= rule.dst_ip_hi)) {
                            // cout << "Cover Rule: (rid=" << rid << "): " << rule.src_ip_lo << "-" << rule.src_ip_hi 
                            // << " , " << rule.dst_ip_lo<< "-" << rule.dst_ip_hi
                            // << endl;
                            covered.push_back(rid);
                        }
                    }
                    bool invalid_cell = cell_is_invalid(covered, ancestors, merged_ip_table);

                    // you asked to collect cells covered by >=2 non-global rules (here S are non-global w.r.t this Rmax)
                    if (!invalid_cell && covered.size() >= 2) {
                        string key = to_string(cell_src_lo) + "-" + to_string(cell_src_hi) + "-" +
                                to_string(cell_dst_lo) + "-" + to_string(cell_dst_hi) + "-" +
                                to_string(proto);
                        if (!seen_keys.count(key)) {
                            local_cells.push_back({cell_src_lo, cell_src_hi, cell_dst_lo, cell_dst_hi, proto, best_rid,covered});
                            seen_keys.insert(key);
                        }
                    }
                }
            }

            for (size_t i = 0; i < S.size(); i++) {
                for (size_t j = i + 1; j < S.size(); j++) {
                    const auto &A = merged_ip_table[S[i]];
                    const auto &B = merged_ip_table[S[j]];

                    uint32_t src_lo = max(A.src_ip_lo, B.src_ip_lo);
                    uint32_t src_hi = min(A.src_ip_hi, B.src_ip_hi);
                    uint32_t dst_lo = max(A.dst_ip_lo, B.dst_ip_lo);
                    uint32_t dst_hi = min(A.dst_ip_hi, B.dst_ip_hi);

                    if (src_lo > src_hi || dst_lo > dst_hi) continue;
                    string key = make_cell_key(proto, src_lo, src_hi, dst_lo, dst_hi);

                    // ✅ 1. 点交：src、dst 都是单点
                    if (src_lo == src_hi && dst_lo == dst_hi) {
                        if (seen_keys.insert(key).second) {
                            local_cells.push_back({src_lo, src_hi, dst_lo, dst_hi, proto, best_rid, {S[i], S[j]}});
                        }
                    }
                    // ✅ 2. 线交：src是点，dst有长度
                    else if (src_lo == src_hi && dst_lo < dst_hi) {
                        if (seen_keys.insert(key).second) {
                            local_cells.push_back({src_lo, src_hi, dst_lo, dst_hi, proto, best_rid, {S[i], S[j]}});
                        }
                    }
                    // ✅ 3. 线交：dst是点，src有长度
                    else if (dst_lo == dst_hi && src_lo < src_hi) {
                        if (seen_keys.insert(key).second) {
                            local_cells.push_back({src_lo, src_hi, dst_lo, dst_hi, proto, best_rid, {S[i], S[j]}});
                        }
                    }

                }
            }

            // remove S rules from remaining (we've processed that dominated region)
            // Build a set of values for fast remove
            unordered_set<size_t> sset(S.begin(), S.end());
            vector<size_t> new_remaining;
            new_remaining.reserve(max<size_t>(1, remaining.size() - S.size()));
            for (size_t rid : remaining) {
                if (sset.find(rid) == sset.end()) new_remaining.push_back(rid);
            }
            remaining.swap(new_remaining);

            // debug log per iteration:
            cout << "[find_intersections] Proto=" << (int)proto
                 << " peeled Rmax=" << best_rid << " covered_count=" << S.size()
                 << " remaining_after=" << remaining.size()
                 << " local_cells_now=" << local_cells.size() << endl;

            // continue loop until remaining < 2
        } // end while remaining

        // append local_cells to global intersections
        size_t before_append = intersections.size();
        intersections.insert(intersections.end(), local_cells.begin(), local_cells.end());
        size_t added = intersections.size() - before_append;

        cout << "[find_intersections] Proto=" << (int)proto
             << " Added cells=" << added << " (local found=" << local_cells.size() << ")\n";
    } // end for each proto

    size_t global_added = intersections.size() - global_before;
    cout << "[find_intersections] Total intersection cells across all protocols="
         << intersections.size() << " (new added=" << global_added << ")\n";
}


void merge_cells_and_ip_table(
    const std::vector<Rmax_IPRule>& Rmax_merged_ip_table,
    const std::vector<IntersectionCell>& intersections,
    std::vector<FinalIPRule>& final_ip_table)
{
    final_ip_table.clear();

    const int NO_RMAX = -1;
    const size_t N = Rmax_merged_ip_table.size();

    // 1) 划分类别：leaders 与 non-leaders（保留原始顺序）
    std::vector<size_t> leader_indices;     // 原始索引（在 Rmax_merged_ip_table 中）
    std::vector<size_t> nonleader_indices;  // 原始索引（在 Rmax_merged_ip_table 中）

    leader_indices.reserve(N);
    nonleader_indices.reserve(N);

    for (size_t i = 0; i < N; ++i) {
        const auto &r = Rmax_merged_ip_table[i];
        // 认为 leader 的判定是 r.rmax_id == i
        if (r.rmax_id == i) {
            leader_indices.push_back(i);
        } else {
            nonleader_indices.push_back(i);
        }
    }

    // 2) 先决定 leaders 在 final_table 中的新位置（他们位于末尾）
    size_t cells_count = intersections.size();
    size_t nonleader_count = nonleader_indices.size();
    size_t leader_count = leader_indices.size();

    size_t leaders_base_index = cells_count + nonleader_count; // leaders 在 final 表中起始索引

    // 构造映射：原始 Rmax_merged_ip_table 索引 -> final 表中索引 (仅对 leader 有映射)
    // 对于不能被识别为 leader 的 r (如 r.rmax_id == SIZE_MAX)，我们不会在 leader_map 中放映射
    std::unordered_map<size_t, size_t> leader_to_final_index;
    leader_to_final_index.reserve(leader_count);
    for (size_t k = 0; k < leader_indices.size(); ++k) {
        size_t orig_idx = leader_indices[k];
        size_t final_idx = leaders_base_index + k;
        leader_to_final_index[orig_idx] = final_idx;
    }

    // 3) 开始构造 final_ip_table（按指定顺序：cells -> nonleaders -> leaders）
    final_ip_table.reserve(cells_count + nonleader_count + leader_count);

    // --- (A) append intersections (cells) ---
    for (size_t i = 0; i < intersections.size(); ++i) {
        const auto &cell = intersections[i];
        FinalIPRule fr;
        fr.src_lo = cell.src_lo;
        fr.src_hi = cell.src_hi;
        fr.dst_lo = cell.dst_lo;
        fr.dst_hi = cell.dst_hi;
        fr.proto  = cell.proto;
        fr.priority = 0;
        fr.is_cell = true;
        fr.is_rmax = false;
        fr.merged_R = cell.rule_indices; // optional

        int own_new_idx = static_cast<int>(final_ip_table.size()); // 当前将被放置的位置
        int rmax_new_idx = NO_RMAX;

        if (cell.rmax_id != SIZE_MAX) {
            auto it = leader_to_final_index.find(cell.rmax_id);
            if (it != leader_to_final_index.end()) rmax_new_idx = static_cast<int>(it->second);
            else rmax_new_idx = NO_RMAX; // 找不到映射，标记为无
        }

        fr.group_ids.clear();
        fr.group_ids.push_back(own_new_idx);
        fr.group_ids.push_back(rmax_new_idx);

        final_ip_table.push_back(std::move(fr));
    }

    // --- (B) append non-leader merged rules (保持原始顺序) ---
    for (size_t idx : nonleader_indices) {
        const auto &r = Rmax_merged_ip_table[idx];
        FinalIPRule fr;
        fr.src_lo = r.src_ip_lo;
        fr.src_hi = r.src_ip_hi;
        fr.dst_lo = r.dst_ip_lo;
        fr.dst_hi = r.dst_ip_hi;
        fr.proto  = r.proto;
        fr.priority = r.priority;
        fr.is_cell = false;
        fr.is_rmax = false;
        fr.merged_R = r.merged_R;

        int own_new_idx = static_cast<int>(final_ip_table.size());
        int rmax_new_idx = NO_RMAX;

        if (r.rmax_id != SIZE_MAX) {
            auto it = leader_to_final_index.find(r.rmax_id);
            if (it != leader_to_final_index.end()) rmax_new_idx = static_cast<int>(it->second);
            else rmax_new_idx = NO_RMAX;
        }

        fr.group_ids.clear();
        fr.group_ids.push_back(own_new_idx);
        fr.group_ids.push_back(rmax_new_idx);

        final_ip_table.push_back(std::move(fr));
    }

    // --- (C) append leaders (Rmax) themselves，按原表顺序 ---
    for (size_t k = 0; k < leader_indices.size(); ++k) {
        size_t orig_idx = leader_indices[k];
        const auto &r = Rmax_merged_ip_table[orig_idx];

        FinalIPRule fr;
        fr.src_lo = r.src_ip_lo;
        fr.src_hi = r.src_ip_hi;
        fr.dst_lo = r.dst_ip_lo;
        fr.dst_hi = r.dst_ip_hi;
        fr.proto  = r.proto;
        fr.priority = r.priority;
        fr.is_cell = false;
        fr.is_rmax = true;
        fr.merged_R = r.merged_R;

        int own_new_idx = static_cast<int>(final_ip_table.size()); // 应等于 leaders_base_index + k
        // leader 只有自己作为 group id（单元素）
        fr.group_ids.clear();
        fr.group_ids.push_back(own_new_idx);

        final_ip_table.push_back(std::move(fr));
    }
    // DEBUG 输出行（可选）
    // cout << "[merge_cells_and_ip_table] final entries = " << final_ip_table.size() << endl;
}




vector<IPRule> split_rule_by_cell(const IPRule &rule, const IntersectionCell &cell) {
    vector<IPRule> output;

    // 如果交集部分完全等于规则的范围，不拆分
    if (cell.src_lo == rule.src_ip_lo && cell.src_hi == rule.src_ip_hi &&
        cell.dst_lo == rule.dst_ip_lo && cell.dst_hi == rule.dst_ip_hi) {
        return output;
    }

    // 辅助函数：用于添加拆分后的规则
    auto add_rule = [&](uint32_t s_lo, uint32_t s_hi,
                        uint32_t d_lo, uint32_t d_hi) {
        if (s_lo <= s_hi && d_lo <= d_hi) {  // 判断拆分后的范围是否合法
            IPRule r = rule;  // 复制原规则
            r.src_ip_lo = s_lo; r.src_ip_hi = s_hi;
            r.dst_ip_lo = d_lo; r.dst_ip_hi = d_hi;
            output.push_back(r);
        }
    };

    // 判断是否是一个“完整”前缀的交集部分，若是，则不需要拆分
    auto is_complete_prefix = [&](uint32_t src_lo, uint32_t src_hi, uint32_t dst_lo, uint32_t dst_hi) {
        // 这里的逻辑是检测源和目的IP是否是前缀形式（是否包含 `*` 或者其对应的范围正好是一个完整的CIDR块）
        return (src_lo == src_hi) && (dst_lo == dst_hi);  // 完全匹配的前缀
    };

    // 判断是否交集部分已经是一个完整的前缀，不需要拆分
    if (is_complete_prefix(cell.src_lo, cell.src_hi, cell.dst_lo, cell.dst_hi)) {
        return output;  // 不需要拆分，直接返回
    }

    // 继续拆分规则，判断上下左右四个区域
    // 上：Dst < cell.dst_lo
    if (rule.dst_ip_lo < cell.dst_lo)
        add_rule(rule.src_ip_lo, rule.src_ip_hi,
                 rule.dst_ip_lo, cell.dst_lo - 1);  // 上方部分

    // 下：
    if (cell.dst_hi < rule.dst_ip_hi)
        add_rule(rule.src_ip_lo, rule.src_ip_hi,
                 cell.dst_hi + 1, rule.dst_ip_hi);  // 下方部分

    // 左：
    if (rule.src_ip_lo < cell.src_lo)
        add_rule(rule.src_ip_lo, cell.src_lo - 1,
                 max(rule.dst_ip_lo, cell.dst_lo),
                 min(rule.dst_ip_hi, cell.dst_hi));  // 左侧部分

    // 右：
    if (cell.src_hi < rule.src_ip_hi)
        add_rule(cell.src_hi + 1, rule.src_ip_hi,
                 max(rule.dst_ip_lo, cell.dst_lo),
                 min(rule.dst_ip_hi, cell.dst_hi));  // 右侧部分

    return output;
}

// 主流程：处理所有cell，拆出extra_rules
void extract_and_split_cells(
        const vector<IPRule> &merged_ip_table,
        const vector<IntersectionCell> &intersections,
        vector<IPRule> &extra_rules) 
{
    for (const auto &cell : intersections) {
        for (size_t rid : cell.rule_indices) {
            const auto &rule = merged_ip_table[rid];
            auto parts = split_rule_by_cell(rule, cell);
            extra_rules.insert(extra_rules.end(), parts.begin(), parts.end());
        }
    }
}


// 计算 rid 在 remaining 中能 cover 哪些 rule（按照 remaining 的内容）
static vector<size_t> get_cover_set(
    const vector<IPRule> &merged_ip_table,
    size_t rid,
    const vector<size_t> &remaining)
{
    vector<size_t> S;
    const IPRule &A = merged_ip_table[rid];
    for (size_t other : remaining) {
        if (other == rid) continue;
        if (covers(A, merged_ip_table[other])) {
            S.push_back(other);
        }
    }
    return S;
}

void find_Rmax_for_merged_ip_table(
    const vector<IPRule>& merged_ip_table,
    vector<Rmax_IPRule>& Rmax_merged_ip_table)
{
    Rmax_merged_ip_table.clear();
    size_t N = merged_ip_table.size();
    Rmax_merged_ip_table.resize(N);
        for (size_t i = 0; i < N; ++i) {
        const auto &r = merged_ip_table[i];
        auto &dst = Rmax_merged_ip_table[i];

        dst.src_ip_lo = r.src_ip_lo;
        dst.src_ip_hi = r.src_ip_hi;
        dst.dst_ip_lo = r.dst_ip_lo;
        dst.dst_ip_hi = r.dst_ip_hi;
        dst.proto = r.proto;
        dst.priority = r.priority;
        dst.src_prefix_len = r.src_prefix_len;
        dst.dst_prefix_len = r.dst_prefix_len;
        dst.merged_R = r.merged_R;

        dst.rmax_id = SIZE_MAX; // 默认无 Rmax
    }

    // 1) bucket rules by proto: map proto -> indices (indices correspond to ip_table)
    map<uint8_t, vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        proto_to_rule_indices[merged_ip_table[i].proto].push_back(i);
    }

    // 2) process each proto separately
    for (const auto& kv : proto_to_rule_indices) {
        uint8_t proto = kv.first;
        vector<size_t> remaining = kv.second; // remaining rules for this proto

        if (remaining.size() < 2) {
            cout << "[find_intersections] Proto=" << (int)proto << " not enough rules, skip\n";
            continue;
        }

        // 反复找 Rmax
        while (remaining.size() >= 2) {
            // 找最佳覆盖规则
            size_t best_pos = find_best_cover_rule_in_set(merged_ip_table, remaining);
            size_t best_rid = remaining[best_pos];

            // 找它覆盖的所有规则 S
            auto S = get_cover_set(merged_ip_table, best_rid, remaining);

            // 给每个 S[x] 标记 rmax_id
            for (size_t covered_rid : S) {
                Rmax_merged_ip_table[covered_rid].rmax_id = best_rid;
            }

            Rmax_merged_ip_table[best_rid].rmax_id = best_rid;
            // 构造 set 用于删除
            unordered_set<size_t> sset(S.begin(), S.end());
            sset.insert(best_rid); // Rmax 本身也踢掉

            // 更新 remaining
            vector<size_t> new_remain;
            new_remain.reserve(remaining.size() - sset.size());
            for (size_t rid : remaining) {
                if (sset.count(rid) == 0)
                    new_remain.push_back(rid);
            }
            remaining.swap(new_remain);
        }
    }

    cout << "[find_Rmax_for_merged_ip_table] Rmax rules filled for "
         << Rmax_merged_ip_table.size() << " entries\n";
}

// --------------- 工具：uint32 → 点分十进制 ----------------
string ip_to_string(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

// ----------- 工具：将 [lo, hi] 转换为 CIDR 列表 -------------
vector<string> range_to_cidrs(uint32_t start, uint32_t end) {
    vector<string> result;

    while (start <= end) {

        uint32_t max_block = start & -start; // 最大对齐块
        int prefix = 32 - __builtin_ctz(max_block);

        // 尝试扩大 CIDR，直到超范围
        while (prefix > 0) {  // **这里防止 prefix=0 再移位 32**
            uint64_t block_size = 1ULL << (32 - prefix);
            uint64_t block_end = (uint64_t)start + block_size - 1;

            if (block_end > end) {
                prefix++;
            } else {
                break;
            }
        }

        // 追加 CIDR
        result.push_back(ip_to_string(start) + "/" + to_string(prefix));

        // 安全计算下一段（不能移位 32）
        uint64_t step = (prefix == 0 ? (1ULL << 32) : (1ULL << (32 - prefix)));

        uint64_t next = (uint64_t)start + step;
        if (next > UINT32_MAX) break;

        start = (uint32_t)next;
    }

    return result;
}


void write_final_table_in_cidr(
    const vector<FinalIPRule>& final_ip_table,
    const string& filename)
{
    ofstream fout(filename);
    if (!fout) {
        cerr << "Error opening output file: " << filename << "\n";
        return;
    }

    fout << "Final IP Table (CIDR only) - " << final_ip_table.size() << " entries\n";

    for (size_t i = 0; i < final_ip_table.size(); ++i) {
        const auto& r = final_ip_table[i];

        fout << "R[" << i << "] PROTO=" << int(r.proto) << " ";

        // SRC
        fout << "SRC{";
        auto src_list = range_to_cidrs(r.src_lo, r.src_hi);
        for (size_t k = 0; k < src_list.size(); ++k) {
            fout << src_list[k];
            if (k + 1 < src_list.size()) fout << ", ";
        }
        fout << "} ";

        // DST
        fout << "DST{";
        auto dst_list = range_to_cidrs(r.dst_lo, r.dst_hi);
        for (size_t k = 0; k < dst_list.size(); ++k) {
            fout << dst_list[k];
            if (k + 1 < dst_list.size()) fout << ", ";
        }
        fout << "} ";

        // Group IDs
        fout << "GIDs{";
        for (size_t k = 0; k < r.group_ids.size(); ++k) {
            fout << r.group_ids[k];
            if (k + 1 < r.group_ids.size()) fout << ", ";
        }
        fout << "}\n";
        cout << "Writing rule " << i << "/" << final_ip_table.size() << endl;
    }

    fout.close();
    cout << "CIDR-format table written to " << filename << endl;
}


/*************************************************************
 * Step 5: main
 *************************************************************/
int main() {
    // 1) load rules and split into ip/port tables
    vector<Rule5D> rules;
    load_rules_from_file("ACL_rules/acl_10k.rules", rules);

    vector<IPRule> ip_table;
    vector<PortRule> port_table;
    split_rules(rules, ip_table, port_table);

    cout << "Total loaded rules: " << rules.size() << endl;
    cout << "IP table entries: " << ip_table.size() << endl;

    // 2) merge identical IP entries
    vector<IPRule> merged_ip_table;
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
    find_intersections_per_proto(merged_ip_table,src_intervals_per_proto, 
        dst_intervals_per_proto, intersections, rmax_rule_ids);

    //add a Gourp_id generator fuction for final table
    // 5) export merged IP table
    ofstream fout1("merged_acl_10k.txt");
    if (!fout1) {
        cerr << "Error: cannot open merged_ip_table.txt for writing.\n";
        return -1;
    }
    fout1 << "Merged IP Table (" << Rmax_merged_ip_table.size() << " entries):\n";
    fout1 << "Idx\tSrcIP_lo\tSrcIP_hi\tDstIP_lo\tDstIP_hi\t"
        << "Proto\tPriority\tSrcMask\tDstMask\tMergedCount\tRmaxID\n";

    for (size_t i = 0; i < Rmax_merged_ip_table.size(); ++i) {
        const auto &r = Rmax_merged_ip_table[i];
        fout1 << i << "\t"
              << r.src_ip_lo << "\t"
              << r.src_ip_hi << "\t"
              << r.dst_ip_lo << "\t"
              << r.dst_ip_hi << "\t"
              << static_cast<int>(r.proto) << "\t"
              << static_cast<int>(r.src_prefix_len) << "\t"
              << static_cast<int>(r.dst_prefix_len) << "\t"
              << r.merged_R.size() << "\t";

                  // 输出 rmax_id
            if (r.rmax_id == SIZE_MAX)
                fout1 << "NONE\t";
            else
                fout1 << r.rmax_id << "\t";
            
            fout1 << "\n"; 
    }
    fout1.close();
    cout << "Merged IP table saved to merged_ip_table.txt" << endl;

    // 6) export intersection cells
    ofstream fout2("intersection_cells.txt");
    if (!fout2) {
        cerr << "Error: cannot open intersection_cells.txt for writing.\n";
        return -1;
    }

    fout2 << "Intersection Cells (" << intersections.size() << " total):\n";
    for (size_t i = 0; i < intersections.size(); ++i) {
        const auto &cell = intersections[i];
        fout2 << "Cell[" << i << "] "
              << "PROTO=" << (int)cell.proto << " "
              << "SRC[" << cell.src_lo << "-" << cell.src_hi << "] "
              << "DST[" << cell.dst_lo << "-" << cell.dst_hi << "] "
              << "Rmax=" << cell.rmax_id << " "
              << "Covered=" << cell.rule_indices.size() << " rules: ";
        for (auto rid : cell.rule_indices) fout2 << rid << " ";
        fout2 << "\n";
    }
    fout2.close();
    cout << "Intersection cells saved to intersection_cells.txt" << endl;

    cout << "============================================\n";
    cout << "All data exported successfully.\n";

    vector<IPRule> extra_rules;
    extract_and_split_cells(merged_ip_table, intersections, extra_rules);
    cout << "[INFO] Extra rules (range only, no CIDR): " << extra_rules.size() << endl;

    ofstream fout_extra("extra_rules.txt");
    for (size_t i = 0; i < extra_rules.size(); ++i) {
        const auto &r = extra_rules[i];
        fout_extra << "ER[" << i << "] PROTO=" << (int)r.proto
                << " SRC[" << r.src_ip_lo << "-"
                << r.src_ip_hi << "] "
                << " DST[" << r.dst_ip_lo << "-"
                << r.dst_ip_hi << "]\n";
    }
    fout_extra.close();

    // 7) merge intersection cells + merged IP table into final table
    vector<FinalIPRule> final_ip_table;
    merge_cells_and_ip_table(Rmax_merged_ip_table, intersections, final_ip_table);
    

    //8) transfer rule into mask type
    // export final IP table
    write_final_table_in_cidr(final_ip_table, "final_ip_table_cidr.txt");
    return 0;
}
