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
#include <iomanip>
#include <queue>  // ★ 添加queue头文件用于BFS优化
#include <cassert>

#include "Loader.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"

using namespace std;


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
            new_rule.merged_R.push_back(i);
            new_rule.rmax_id = i; // 初始化rmax_id为自身索引

            merged_ip_table.push_back(new_rule);
            key_to_index[key] = merged_ip_table.size() - 1;
        } else {
            size_t idx = it->second;
            merged_ip_table[idx].merged_R.push_back(i);
        }
    }

    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        merged_ip_table[i].priority = static_cast<uint32_t>(i + 1);
        merged_ip_table[i].rmax_id = i; // 确保rmax_id初始化为自身索引
    }

    std::cout << "[merge_same_ip_entry] Original IP rules = " << ip_table.size()
              << ", merged = " << merged_ip_table.size() << std::endl;
}


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
    }
}


static inline bool covers(const IPRule& A, const IPRule& B) {
    if (&A == &B) return false;
    return (A.src_ip_lo <= B.src_ip_lo &&
            A.src_ip_hi >= B.src_ip_hi &&
            A.dst_ip_lo <= B.dst_ip_lo &&
            A.dst_ip_hi >= B.dst_ip_hi);
}


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


static inline string make_cell_key(uint8_t proto,
                                   uint32_t s_lo, uint32_t s_hi,
                                   uint32_t d_lo, uint32_t d_hi) {
    // compact string key for dedupe
    std::ostringstream oss;
    oss << (int)proto << ":" << s_lo << "-" << s_hi << ":" << d_lo << "-" << d_hi;
    return oss.str();
}


void collect_line_and_point_cells(
    const vector<IPRule>& ip_table,
    const vector<size_t>& proto_rules,
    uint8_t proto,
    vector<IntersectionCell>& local_cells,
    unordered_set<string>& seen_keys,
    size_t rmax_id
 )
{   
    // Helper: check if a cell is duplicate of any merged_ip_table rule
    auto is_duplicate_of_merged_rule = [&](uint32_t s_lo, uint32_t s_hi, 
                                           uint32_t d_lo, uint32_t d_hi) -> bool {
        for (size_t rid : proto_rules) {
            const IPRule &R = ip_table[rid];
            if (R.src_ip_lo == s_lo && R.src_ip_hi == s_hi &&
                R.dst_ip_lo == d_lo && R.dst_ip_hi == d_hi) {
                return true;  // Found an identical rule
            }
        }
        return false;
    };

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
                if (is_duplicate_of_merged_rule(px, px, dlo, dhi)) {
                    continue;  // Skip identical cell
                }
                
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
                        // ★ Extraction 应存储 merged_ip_table 索引，而非原始规则 ID
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({px, px, dlo, dhi, proto, rmax_id, covered, Extraction});
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
                    if (is_duplicate_of_merged_rule(slo, shi, py, py)) {
                        continue;  
                    }
                    
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
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({slo, shi, py, py, proto, rmax_id, covered, Extraction});
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
                
                if (is_duplicate_of_merged_rule(px, px, py, py)) {
                    goto skip_point_1; 
                }
                
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
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered, Extraction});
                    }
                }
            }
            skip_point_1:
            if (src_touch_ab && dst_touch_ba) {
                uint32_t px = A.src_ip_hi, py = B.dst_ip_hi;
                
                // Check if identical to any merged_ip_table rule
                if (is_duplicate_of_merged_rule(px, px, py, py)) {
                    goto skip_point_2;  
                }
                
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
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered, Extraction});
                    }
                }
            }
            skip_point_2:
            if (src_touch_ba && dst_touch_ab) {
                uint32_t px = B.src_ip_hi, py = A.dst_ip_hi;
                
                if (is_duplicate_of_merged_rule(px, px, py, py)) {
                    goto skip_point_3;  
                }
                
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
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered, Extraction});
                    }
                }
            }
            skip_point_3:
            if (src_touch_ba && dst_touch_ba) {
                uint32_t px = B.src_ip_hi, py = B.dst_ip_hi;
                
                if (is_duplicate_of_merged_rule(px, px, py, py)) {
                    goto skip_point_4;  
                }
                
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
                        vector<size_t> Extraction = {proto_rules[ia], proto_rules[ib]};
                        local_cells.push_back({px, px, py, py, proto, rmax_id, covered, Extraction});
                    }
                }
            }
            skip_point_4:
            ; 
        } // ib
    } // ia
}


static void build_ancestors(
    const vector<size_t>& remaining,
    const vector<IPRule>& merged_ip_table,
    unordered_map<size_t, vector<size_t>>& ancestors,
    size_t rmax_id
)
{
    vector<size_t> rem = remaining;
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


static bool cell_is_invalid(
    const vector<size_t>& covered,
    const unordered_map<size_t, vector<size_t>>& ancestors,
    const vector<IPRule>& merged_ip_table,
    vector<size_t>& out_minimal,
    uint32_t cell_src_lo, uint32_t cell_src_hi,
    uint32_t cell_dst_lo, uint32_t cell_dst_hi
)
{
    if (covered.size() < 2) return true;

    // ★ 修复1: 先去重 covered 列表
    vector<size_t> unique_covered;
    unordered_set<size_t> seen;
    for (size_t rid : covered) {
        if (seen.insert(rid).second) {
            unique_covered.push_back(rid);
        }
    }
    
    if (unique_covered.size() < 2) return true;

    // Ancestor redundancy check
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

    if (redundant_via_ancestors(unique_covered)) {
        return true;
    }

    // ★★★ 新方案: 识别真正参与相交的规则 ★★★
    // 核心思路: 真正的相交规则是那些与其他规则"真正相交"（部分重叠）的规则
    //          而不是完全包含或被完全包含的规则
    vector<size_t> minimal;
    minimal.reserve(unique_covered.size());

    // 检查两个规则是否"真正相交"（部分重叠，但非完全包含）
    auto is_proper_intersection = [&](size_t r1, size_t r2) -> bool {
        const auto& a = merged_ip_table[r1];
        const auto& b = merged_ip_table[r2];
        
        // 首先检查是否有交集
        bool has_overlap = (a.src_ip_lo <= b.src_ip_hi && b.src_ip_lo <= a.src_ip_hi) &&
                          (a.dst_ip_lo <= b.dst_ip_hi && b.dst_ip_lo <= a.dst_ip_hi);
        if (!has_overlap) return false;
        
        // 检查是否是完全包含关系（一个完全包含另一个）
        bool a_contains_b = (a.src_ip_lo <= b.src_ip_lo && a.src_ip_hi >= b.src_ip_hi &&
                            a.dst_ip_lo <= b.dst_ip_lo && a.dst_ip_hi >= b.dst_ip_hi);
        bool b_contains_a = (b.src_ip_lo <= a.src_ip_lo && b.src_ip_hi >= a.src_ip_hi &&
                            b.dst_ip_lo <= a.dst_ip_lo && b.dst_ip_hi >= a.dst_ip_hi);
        
        // 真正的相交 = 有交集 但 不是完全包含关系
        return has_overlap && !a_contains_b && !b_contains_a;
    };

    // 对每个covered规则，检查它是否与其他规则"真正相交"
    for (size_t r : unique_covered) {
        bool has_proper_intersection = false;
        
        for (size_t s : unique_covered) {
            if (r == s) continue;
            if (is_proper_intersection(r, s)) {
                has_proper_intersection = true;
                break;
            }
        }
        
        // 只保留与其他规则有真正相交的规则
        if (has_proper_intersection) {
            minimal.push_back(r);
        }
    }

    out_minimal = minimal;
    // Validity check
    return (minimal.size() < 2);
}

void Map_cell_to_origID(
    const vector<IPRule>& merged_ip_table,
    const vector<size_t>& idx_list,
    vector<size_t>& out_orig_ids)
{
    out_orig_ids.clear();
    unordered_set<size_t> uniq;

    for (size_t mid : idx_list) {
        if (mid >= merged_ip_table.size()) continue;

        const auto& R = merged_ip_table[mid];
        for (size_t orig : R.merged_R) {
            uniq.insert(orig);   // 去重
        }
    }

    out_orig_ids.assign(uniq.begin(), uniq.end());
}


struct ProtoProcessContext {
    uint8_t proto;
    size_t best_rid;
    const IPRule& Rmax;
    const vector<size_t>& S;
    const vector<IPRule>& merged_ip_table;
    unordered_set<string>& seen_keys;
    vector<IntersectionCell>& local_cells;
    const unordered_map<size_t, vector<size_t>>& ancestors;
};

static inline vector<size_t> compute_covered_set(
    const IPRule& Rmax,
    const vector<size_t>& remaining,
    const vector<IPRule>& merged_ip_table)
{
    vector<size_t> S;
    S.reserve(remaining.size());
    
    for (size_t rid : remaining) {
        if (covers(Rmax, merged_ip_table[rid])) {
            S.push_back(rid);
        }
    }
    return S;
}

//Find the index range of endpoints within Rmax range
struct IntervalBounds {
    size_t start_idx;
    size_t end_idx;
};

static inline IntervalBounds find_endpoint_bounds(
    const vector<uint32_t>& endpoints,
    uint32_t range_lo,
    uint32_t range_hi)
{
    IntervalBounds bounds{0, 0};
    
    bounds.start_idx = std::lower_bound(endpoints.begin(), endpoints.end(), range_lo) - endpoints.begin();
    bounds.end_idx = std::upper_bound(endpoints.begin(), endpoints.end(), range_hi) - endpoints.begin();
    
    return bounds;
}

static inline bool is_duplicate_in_set(
    uint32_t src_lo, uint32_t src_hi,
    uint32_t dst_lo, uint32_t dst_hi,
    const vector<size_t>& rule_set,
    const vector<IPRule>& merged_ip_table)
{
    for (size_t rid : rule_set) {
        const IPRule& R = merged_ip_table[rid];
        if (R.src_ip_lo == src_lo && R.src_ip_hi == src_hi &&
            R.dst_ip_lo == dst_lo && R.dst_ip_hi == dst_hi) {
            return true;
        }
    }
    return false;
}

// =====================================================================
// 连续区域重建辅助函数
// =====================================================================

// 检查规则 r1 是否在全局空间中完全包含规则 r2
static inline bool rule_contains_in_global(
    size_t r1, size_t r2,
    const vector<IPRule>& merged_ip_table)
{
    const auto& a = merged_ip_table[r1];
    const auto& b = merged_ip_table[r2];
    return (a.src_ip_lo <= b.src_ip_lo && a.src_ip_hi >= b.src_ip_hi &&
            a.dst_ip_lo <= b.dst_ip_lo && a.dst_ip_hi >= b.dst_ip_hi);
}

// 计算两个 minimal 集合的交集
static inline vector<size_t> compute_common_rules(
    const vector<size_t>& a,
    const vector<size_t>& b)
{
    vector<size_t> common;
    for (size_t r : a) {
        if (find(b.begin(), b.end(), r) != b.end()) {
            common.push_back(r);
        }
    }
    return common;
}

// 筛选公共规则：去掉完全包含其他规则的"干扰大规则"
static inline vector<size_t> filter_common_rules(
    const vector<size_t>& common,
    const vector<IPRule>& merged_ip_table)
{
    vector<size_t> filtered;
    for (size_t r : common) {
        bool is_container = false;
        for (size_t s : common) {
            if (r != s && rule_contains_in_global(r, s, merged_ip_table)) {
                is_container = true;
                break;
            }
        }
        if (!is_container) {
            filtered.push_back(r);
        }
    }
    return filtered;
}

// 检查两个 cell 是否空间相邻（可以合并）
static inline bool cells_are_adjacent(
    const IntersectionCell& a,
    const IntersectionCell& b)
{
    // Src 维度相邻或包含
    bool src_adj = (a.src_hi + 1 == b.src_lo) || (b.src_hi + 1 == a.src_lo) ||
                   (a.src_lo <= b.src_lo && b.src_hi <= a.src_hi) ||
                   (b.src_lo <= a.src_lo && a.src_hi <= b.src_hi);
    // Dst 维度相邻或包含
    bool dst_adj = (a.dst_hi + 1 == b.dst_lo) || (b.dst_hi + 1 == a.dst_lo) ||
                   (a.dst_lo <= b.dst_lo && b.dst_hi <= a.dst_hi) ||
                   (b.dst_lo <= a.dst_lo && a.dst_hi <= b.dst_hi);
    // Src/Dst 维度重叠
    bool src_overlap = (a.src_lo <= b.src_hi && b.src_lo <= a.src_hi);
    bool dst_overlap = (a.dst_lo <= b.dst_hi && b.dst_lo <= a.dst_hi);
    
    return (src_adj && dst_overlap) || (dst_adj && src_overlap);
}

// =====================================================================
// rebuild_continuous_cells: 连续区域重建
// =====================================================================
// 
// 功能：合并具有相同公共规则且空间相邻的 cells，减少冗余
// 
// 算法（自顶向下逐层剥离）：
// 1. 按 minimal.size() 降序排序所有 cells
// 2. 从最大的 cell 开始，寻找可以匹配的较小 cell
// 3. 匹配条件：公共规则 >= 2，且在全局空间中大的包含小的
// 4. 匹配成功后：小 cell 扩展范围，大 cell 的 minimal 减小到公共部分
//
static void rebuild_continuous_cells(
    vector<IntersectionCell>& cells,
    const vector<IPRule>& merged_ip_table)
{
    if (cells.size() < 2) return;

    // 按 minimal.size() 降序排序索引
    vector<size_t> sorted_idx(cells.size());
    for (size_t i = 0; i < cells.size(); ++i) sorted_idx[i] = i;
    sort(sorted_idx.begin(), sorted_idx.end(), [&](size_t a, size_t b) {
        return cells[a].minimal.size() > cells[b].minimal.size();
    });

    // 自顶向下处理
    for (size_t idx : sorted_idx) {
        auto& big = cells[idx];
        if (big.minimal.size() < 3) continue;  // minimal <= 2 无需简化

        // 寻找最佳匹配
        size_t best_match = SIZE_MAX;
        size_t best_score = 0;
        vector<size_t> best_common;

        for (size_t j = 0; j < cells.size(); ++j) {
            if (j == idx) continue;
            auto& small = cells[j];
            
            // 条件：minimal 更小、空间相邻
            if (small.minimal.size() >= big.minimal.size()) continue;
            if (!cells_are_adjacent(big, small)) continue;
            
            // 计算并筛选公共规则
            auto common = compute_common_rules(big.minimal, small.minimal);
            if (common.size() < 2) continue;
            auto filtered = filter_common_rules(common, merged_ip_table);
            if (filtered.size() < 2) continue;
            
            // 选择最佳匹配（公共规则最多）
            if (filtered.size() > best_score) {
                best_score = filtered.size();
                best_match = j;
                best_common = filtered;
            }
        }

        // 执行合并
        if (best_match != SIZE_MAX) {
            auto& small = cells[best_match];
            
            // 扩展 small 的范围（取并集）
            small.src_lo = min(small.src_lo, big.src_lo);
            small.src_hi = max(small.src_hi, big.src_hi);
            small.dst_lo = min(small.dst_lo, big.dst_lo);
            small.dst_hi = max(small.dst_hi, big.dst_hi);
            
            // 更新 big 的 minimal 和 Extraction（注意：priority 不变）
            big.minimal = best_common;
            Map_cell_to_origID(merged_ip_table, best_common, big.Extraction);
        }
    }

    // ========== 按优先级排序：priority 越大（初始 minimal 越多）排越前面 ==========
    sort(cells.begin(), cells.end(), [](const IntersectionCell& a, const IntersectionCell& b) {
        return a.priority > b.priority;  // 降序
    });
}

// =====================================================================
// collect_elementary_cells: 收集区间相交产生的 cells 并进行连续区域重建
// =====================================================================
//
// 流程：
// 1. 枚举所有 elementary cells（由端点划分的区间）
// 2. 对每个 cell 计算 covered 规则和 minimal 集合
// 3. 收集所有有效 cells 到临时列表
// 4. 在同一 Rmax 区域内执行连续区域重建（合并相邻 cells）
// 5. 将结果添加到 local_cells
//
static void collect_elementary_cells(
    const ProtoProcessContext& ctx,
    const vector<uint32_t>& src_ep,
    const vector<uint32_t>& dst_ep)
{
    // ========== Phase 1: 枚举并收集所有有效 cells ==========
    
    vector<IntersectionCell> temp_cells;  // 临时存储本轮收集的 cells
    
    auto src_bounds = find_endpoint_bounds(src_ep, ctx.Rmax.src_ip_lo, ctx.Rmax.src_ip_hi);
    auto dst_bounds = find_endpoint_bounds(dst_ep, ctx.Rmax.dst_ip_lo, ctx.Rmax.dst_ip_hi);
    
    for (size_t si = src_bounds.start_idx; si + 1 < src_ep.size() && si + 1 <= src_bounds.end_idx; ++si) {
        uint32_t cell_src_lo = src_ep[si];
        uint32_t cell_src_hi = src_ep[si + 1];
        if (cell_src_hi == 0) cell_src_hi = numeric_limits<uint32_t>::max();
        
        if (cell_src_lo < ctx.Rmax.src_ip_lo || cell_src_hi > ctx.Rmax.src_ip_hi) continue;

        for (size_t dj = dst_bounds.start_idx; dj + 1 < dst_ep.size() && dj + 1 <= dst_bounds.end_idx; ++dj) {
            uint32_t cell_dst_lo = dst_ep[dj];
            uint32_t cell_dst_hi = dst_ep[dj + 1];
            if (cell_dst_hi == 0) cell_dst_hi = numeric_limits<uint32_t>::max();
            
            if (cell_dst_lo < ctx.Rmax.dst_ip_lo || cell_dst_hi > ctx.Rmax.dst_ip_hi) continue;

            // 跳过与现有规则完全相同的 cell
            if (is_duplicate_in_set(cell_src_lo, cell_src_hi, cell_dst_lo, cell_dst_hi, 
                                   ctx.S, ctx.merged_ip_table)) continue;

            // 找出覆盖此 cell 的所有规则
            vector<size_t> covered;
            for (size_t rid : ctx.S) {
                const auto& rule = ctx.merged_ip_table[rid];
                if (rule.src_ip_lo <= cell_src_lo && cell_src_hi <= rule.src_ip_hi &&
                    rule.dst_ip_lo <= cell_dst_lo && cell_dst_hi <= rule.dst_ip_hi) {
                    covered.push_back(rid);
                }
            }

            // 验证 cell 有效性，计算 minimal
            vector<size_t> minimal;
            if (cell_is_invalid(covered, ctx.ancestors, ctx.merged_ip_table, minimal,
                               cell_src_lo, cell_src_hi, cell_dst_lo, cell_dst_hi)) {
                continue;
            }
            if (covered.size() < 2) continue;

            // 去重检查
            string key = to_string(cell_src_lo) + "-" + to_string(cell_src_hi) + "-" +
                        to_string(cell_dst_lo) + "-" + to_string(cell_dst_hi) + "-" +
                        to_string(ctx.proto);
            if (!ctx.seen_keys.insert(key).second) continue;

            // 创建 cell
            IntersectionCell cell;
            cell.src_lo = cell_src_lo;
            cell.src_hi = cell_src_hi;
            cell.dst_lo = cell_dst_lo;
            cell.dst_hi = cell_dst_hi;
            cell.proto = ctx.proto;
            cell.rmax_id = ctx.best_rid;
            cell.rule_indices = covered;
            cell.minimal = minimal;
            cell.priority = minimal.size();  // ★ 优先级 = 初始 minimal 数量
            Map_cell_to_origID(ctx.merged_ip_table, minimal, cell.Extraction);
            
            temp_cells.push_back(cell);
            
        }
    }

    // ========== Phase 2: 连续区域重建 ==========
    rebuild_continuous_cells(temp_cells, ctx.merged_ip_table);

    // ========== Phase 3: 将结果添加到 local_cells ==========
    
    for (auto& cell : temp_cells) {
        ctx.local_cells.push_back(cell);
    }
}

// 5. Collect pairwise intersections (point and line intersections)
static void collect_pairwise_intersections(const ProtoProcessContext& ctx)
{
    const size_t n = ctx.S.size();
    
    for (size_t i = 0; i < n; ++i) {
        for (size_t j = i + 1; j < n; ++j) {
            const auto& A = ctx.merged_ip_table[ctx.S[i]];
            const auto& B = ctx.merged_ip_table[ctx.S[j]];

            uint32_t src_lo = max(A.src_ip_lo, B.src_ip_lo);
            uint32_t src_hi = min(A.src_ip_hi, B.src_ip_hi);
            uint32_t dst_lo = max(A.dst_ip_lo, B.dst_ip_lo);
            uint32_t dst_hi = min(A.dst_ip_hi, B.dst_ip_hi);

            // 无交集或与已有规则重复
            if (src_lo > src_hi || dst_lo > dst_hi) continue;
            if (is_duplicate_in_set(src_lo, src_hi, dst_lo, dst_hi, ctx.S, ctx.merged_ip_table)) 
                continue;

            // 只处理点交和线交（非面交）
            bool is_point = (src_lo == src_hi && dst_lo == dst_hi);
            bool is_line = (src_lo == src_hi && dst_lo < dst_hi) || 
                          (dst_lo == dst_hi && src_lo < src_hi);
            
            if (!is_point && !is_line) continue;

            string key = make_cell_key(ctx.proto, src_lo, src_hi, dst_lo, dst_hi);
            if (ctx.seen_keys.insert(key).second) {
                vector<size_t> Extraction;
                Map_cell_to_origID(ctx.merged_ip_table, {ctx.S[i], ctx.S[j]}, Extraction);
                ctx.local_cells.push_back({src_lo, src_hi, dst_lo, dst_hi, ctx.proto, 
                                          ctx.best_rid, {ctx.S[i], ctx.S[j]}, Extraction});
            }
        }
    }
}

// 6. 移除已处理的规则（优化版本）
static void remove_processed_rules(vector<size_t>& remaining, const vector<size_t>& to_remove)
{
    if (to_remove.empty()) return;
    
    // 使用unordered_set加速查找
    unordered_set<size_t> remove_set(to_remove.begin(), to_remove.end());
    
    // 使用erase-remove idiom（更高效）
    remaining.erase(
        std::remove_if(remaining.begin(), remaining.end(),
            [&remove_set](size_t rid) { return remove_set.count(rid) > 0; }),
        remaining.end()
    );
}


void find_intersections_per_proto(
    const std::vector<IPRule>& merged_ip_table,
    const std::map<uint8_t, std::vector<uint32_t>>& src_intervals_per_proto,
    const std::map<uint8_t, std::vector<uint32_t>>& dst_intervals_per_proto,
    std::vector<IntersectionCell>& intersections,
    std::vector<size_t>& rmax_rule_ids)  
{
    size_t global_before = intersections.size();

    //1) per-protocol rule indices
    map<uint8_t, vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < merged_ip_table.size(); ++i) {
        proto_to_rule_indices[merged_ip_table[i].proto].push_back(i);
    }

    //2) process each protocol separately
    for (const auto& [proto, initial_remaining] : proto_to_rule_indices) {
        auto it_src = src_intervals_per_proto.find(proto);
        auto it_dst = dst_intervals_per_proto.find(proto);
        if (it_src == src_intervals_per_proto.end() || it_dst == dst_intervals_per_proto.end()) {
            continue;
        }
        const auto& src_ep = it_src->second;
        const auto& dst_ep = it_dst->second;

        if (initial_remaining.size() < 2) {
            cout << "[find_intersections] Proto=" << (int)proto << " not enough rules, skip\n";
            continue;
        }

        vector<IntersectionCell> local_cells;
        unordered_set<string> seen_keys;
        vector<size_t> remaining = initial_remaining;
       
        //3) Find intersections within this protocol region
        while (remaining.size() >= 2) {
            // 3.1 Find Rmax and kick off
            size_t best_pos = find_best_cover_rule_in_set(merged_ip_table, remaining);
            size_t best_rid = remaining[best_pos];
            const auto& Rmax = merged_ip_table[best_rid];
            rmax_rule_ids.push_back(best_rid);

            // 3.2 build ancestors
            unordered_map<size_t, vector<size_t>> ancestors;        
            build_ancestors(remaining, merged_ip_table, ancestors, best_rid);
            
            // 3.3 Collect line and point intersections in R (boundary cases)
            collect_line_and_point_cells(merged_ip_table, remaining, proto, local_cells, seen_keys, best_rid);  

            // 3.4 Compute the set of rules covered by Rmax
            vector<size_t> S = compute_covered_set(Rmax, remaining, merged_ip_table);
            
            if (S.size() < 2) {
                remaining.erase(remaining.begin() + best_pos);
                continue;
            }

            // 3.5 Build processing context
            ProtoProcessContext ctx{
                proto, best_rid, Rmax, S, merged_ip_table, 
                seen_keys, local_cells, ancestors
            };

            // 3.6 Collect elementary cells (region intersections in S)
            collect_elementary_cells(ctx, src_ep, dst_ep);

            // 3.7 Collect pairwise intersections (point and line intersections in S)
            collect_pairwise_intersections(ctx);

            // 3.8 Remove processed rules
            remove_processed_rules(remaining, S);
        }

        // 4. Merge into global results
        intersections.insert(intersections.end(), local_cells.begin(), local_cells.end());
    }
    
    size_t global_added = intersections.size() - global_before;
    cout << "[find_intersections] Total intersection cells across all protocols="
         << intersections.size() << " (new added=" << global_added << ")\n";
}


// 过滤Rmax_intersections中与intersections重复的规则
// 重复定义：源IP、目的IP和协议都相同的规则
std::vector<IntersectionCell> filter_duplicate_rmax_intersections(
    const std::vector<IntersectionCell>& Rmax_intersections,
    const std::vector<IntersectionCell>& intersections)
{
    // 创建一个用于去重的集合，存储intersections中的规则特征
    std::unordered_set<std::string> intersection_keys;
    for (const auto& cell : intersections) {
        std::string key = std::to_string(cell.src_lo) + "-" + std::to_string(cell.src_hi) + "-" +
                         std::to_string(cell.dst_lo) + "-" + std::to_string(cell.dst_hi) + "-" +
                         std::to_string(cell.proto);
        intersection_keys.insert(key);
    }

    // 创建过滤后的Rmax_intersections，去除与intersections重复的规则
    std::vector<IntersectionCell> filtered_Rmax_intersections;
    for (const auto& rmax_cell : Rmax_intersections) {
        std::string key = std::to_string(rmax_cell.src_lo) + "-" + std::to_string(rmax_cell.src_hi) + "-" +
                         std::to_string(rmax_cell.dst_lo) + "-" + std::to_string(rmax_cell.dst_hi) + "-" +
                         std::to_string(rmax_cell.proto);
        
        // 如果在intersections中找不到相同的规则，则保留
        if (intersection_keys.find(key) == intersection_keys.end()) {
            filtered_Rmax_intersections.push_back(rmax_cell);
        }
    }
    
    return filtered_Rmax_intersections;
}

void merge_cells_and_ip_table(
    const std::vector<Rmax_IPRule>& OR_merged_ip_table,
    const std::vector<IntersectionCell>& intersections,
    const std::vector<IntersectionCell>& Rmax_intersections,
    std::vector<FinalIPRule>& final_ip_table)
{
    final_ip_table.clear();

    // 过滤掉与 intersections 重复的 Rmax_intersections
    std::vector<IntersectionCell> filtered_Rmax_intersections =
        filter_duplicate_rmax_intersections(Rmax_intersections, intersections);

    const int NO_RMAX = -1;
    const size_t N = OR_merged_ip_table.size();

    /*------------------------------------------------------------
     * 1) leader / non-leader 划分
     *------------------------------------------------------------*/
    std::vector<size_t> leader_indices;
    std::vector<size_t> nonleader_indices;

    for (size_t i = 0; i < N; ++i) {
        if (OR_merged_ip_table[i].rmax_id == i)
            leader_indices.push_back(i);
        else
            nonleader_indices.push_back(i);
    }

    final_ip_table.reserve(
        intersections.size() +
        filtered_Rmax_intersections.size() +
        nonleader_indices.size() +
        leader_indices.size());

    std::unordered_set<std::string> added_rules;

    auto make_key = [](uint32_t sl, uint32_t sh,
                       uint32_t dl, uint32_t dh,
                       uint8_t proto) {
        return std::to_string(sl) + "-" + std::to_string(sh) + "-" +
               std::to_string(dl) + "-" + std::to_string(dh) + "-" +
               std::to_string(proto);
    };

    /*------------------------------------------------------------
     * (A) intersections
     *------------------------------------------------------------*/
    for (const auto& cell : intersections) {
        FinalIPRule fr{};
        fr.src_lo = cell.src_lo;
        fr.src_hi = cell.src_hi;
        fr.dst_lo = cell.dst_lo;
        fr.dst_hi = cell.dst_hi;
        fr.proto  = cell.proto;
        fr.priority = 0;
        fr.is_cell = true;
        fr.is_rmax = false;
        fr.merged_R = cell.rule_indices;
        fr.original_merged_index =
            cell.Extraction.empty() ? SIZE_MAX : cell.Extraction[0];

        int own_idx = static_cast<int>(final_ip_table.size());
        fr.group_ids = { own_idx };

        if (cell.rmax_id != SIZE_MAX &&
            cell.rmax_id < OR_merged_ip_table.size())
        {
            // 检查是否是 leader
            size_t rmax_idx = cell.rmax_id;
            size_t rmax_leader_id = OR_merged_ip_table[rmax_idx].rmax_id;
            if (rmax_leader_id == rmax_idx) {
                // ★ 只记录 leader 的 orig_idx（负数编码）
                fr.group_ids.push_back(-static_cast<int>(rmax_idx) - 1);
            }
        }

        final_ip_table.push_back(std::move(fr));
        added_rules.insert(
            make_key(cell.src_lo, cell.src_hi,
                     cell.dst_lo, cell.dst_hi,
                     cell.proto));
    }

    /*------------------------------------------------------------
     * (B) Rmax intersections
     *------------------------------------------------------------*/
    for (const auto& cell : filtered_Rmax_intersections) {
        std::string key =
            make_key(cell.src_lo, cell.src_hi,
                     cell.dst_lo, cell.dst_hi,
                     cell.proto);

        if (added_rules.count(key))
            continue;

        if (cell.rmax_id == SIZE_MAX ||
            cell.rmax_id >= OR_merged_ip_table.size() ||
            OR_merged_ip_table[cell.rmax_id].rmax_id != cell.rmax_id)
            continue; // 没 leader 的 B-cell 丢弃

        FinalIPRule fr{};
        fr.src_lo = cell.src_lo;
        fr.src_hi = cell.src_hi;
        fr.dst_lo = cell.dst_lo;
        fr.dst_hi = cell.dst_hi;
        fr.proto  = cell.proto;
        fr.priority = 1;
        fr.is_cell = true;
        fr.is_rmax = false;
        fr.merged_R = cell.rule_indices;
        fr.original_merged_index =
            cell.Extraction.empty() ? SIZE_MAX : cell.Extraction[0];

        int own_idx = static_cast<int>(final_ip_table.size());
        fr.group_ids = {
            own_idx,
            -static_cast<int>(cell.rmax_id) - 1
        };

        final_ip_table.push_back(std::move(fr));
        added_rules.insert(key);
    }

    /*------------------------------------------------------------
     * (C) non-leaders
     *------------------------------------------------------------*/
    for (size_t idx : nonleader_indices) {
        const auto& r = OR_merged_ip_table[idx];

        std::string key =
            make_key(r.src_ip_lo, r.src_ip_hi,
                     r.dst_ip_lo, r.dst_ip_hi,
                     r.proto);

        if (added_rules.count(key))
            continue;

        FinalIPRule fr{};
        fr.src_lo = r.src_ip_lo;
        fr.src_hi = r.src_ip_hi;
        fr.dst_lo = r.dst_ip_lo;
        fr.dst_hi = r.dst_ip_hi;
        fr.proto  = r.proto;
        fr.priority = r.priority;
        fr.is_cell = false;
        fr.is_rmax = false;
        fr.merged_R = r.merged_R;
        fr.original_merged_index = idx;

        int own_idx = static_cast<int>(final_ip_table.size());
        fr.group_ids = { own_idx };

        if (r.rmax_id != SIZE_MAX &&
            r.rmax_id < OR_merged_ip_table.size())
        {
            // 检查是否是 leader
            if (OR_merged_ip_table[r.rmax_id].rmax_id == r.rmax_id) {
                fr.group_ids.push_back(-static_cast<int>(r.rmax_id) - 1);
            }
        }

        final_ip_table.push_back(std::move(fr));
        added_rules.insert(key);
    }

    /*------------------------------------------------------------
     * (D) leaders（记录真实 index）
     *------------------------------------------------------------*/
    std::unordered_map<size_t, int> leader_real_index;

    for (size_t orig_idx : leader_indices) {
        const auto& r = OR_merged_ip_table[orig_idx];

        std::string key =
            make_key(r.src_ip_lo, r.src_ip_hi,
                     r.dst_ip_lo, r.dst_ip_hi,
                     r.proto);

        if (added_rules.count(key))
            continue;

        int real_idx = static_cast<int>(final_ip_table.size());
        leader_real_index[orig_idx] = real_idx;

        FinalIPRule fr{};
        fr.src_lo = r.src_ip_lo;
        fr.src_hi = r.src_ip_hi;
        fr.dst_lo = r.dst_ip_lo;
        fr.dst_hi = r.dst_ip_hi;
        fr.proto  = r.proto;
        fr.priority = r.priority;
        fr.is_cell = false;
        fr.is_rmax = true;
        fr.merged_R = r.merged_R;
        fr.original_merged_index = orig_idx;
        fr.group_ids = { real_idx };

        final_ip_table.push_back(std::move(fr));
        added_rules.insert(key);
    }

    /*------------------------------------------------------------
     * ★ FINAL FIX：回填 leader index
     *------------------------------------------------------------*/
    for (auto& fr : final_ip_table) {
        for (int& gid : fr.group_ids) {
            if (gid < 0) {
                size_t leader_orig = static_cast<size_t>(-gid - 1);
                auto it = leader_real_index.find(leader_orig);
                assert(it != leader_real_index.end());
                gid = it->second;
            }
        }
    }

    
#ifndef NDEBUG
    // 最终一致性校验
    for (size_t i = 0; i < final_ip_table.size(); ++i) {
        for (int gid : final_ip_table[i].group_ids) {
            assert(gid >= 0 &&
                   gid < static_cast<int>(final_ip_table.size()));
        }
    }
#endif
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
    const size_t N = merged_ip_table.size();
    Rmax_merged_ip_table.clear();
    Rmax_merged_ip_table.reserve(N);
    
    // Step 1: Initialize Rmax_merged_ip_table (each rule is its own Rmax by default)
    for (size_t i = 0; i < N; ++i) {
        const auto &src = merged_ip_table[i];
        Rmax_IPRule dst;
        
        // Copy IP rule fields
        dst.src_ip_lo = src.src_ip_lo;
        dst.src_ip_hi = src.src_ip_hi;
        dst.dst_ip_lo = src.dst_ip_lo;
        dst.dst_ip_hi = src.dst_ip_hi;
        dst.proto = src.proto;
        dst.priority = src.priority;
        dst.src_prefix_len = src.src_prefix_len;
        dst.dst_prefix_len = src.dst_prefix_len;
        dst.merged_R = src.merged_R;
        dst.rmax_id = i;  // Default: each rule is its own Rmax
        
        Rmax_merged_ip_table.push_back(std::move(dst));
    }

    // Step 2: Group rules by protocol for independent processing
    map<uint8_t, vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < N; ++i) {
        proto_to_rule_indices[merged_ip_table[i].proto].push_back(i);
    }

    // Step 3: Process each protocol independently
    for (const auto& [proto, initial_rules] : proto_to_rule_indices) {
        if (initial_rules.size() < 2) {
            // Single rule: no Rmax computation needed
            continue;
        }

        vector<size_t> remaining = initial_rules;

        // Iteratively peel off Rmax-dominated subsets
        while (remaining.size() >= 2) {
            // Find best cover rule (Rmax) in remaining set
            size_t best_pos = find_best_cover_rule_in_set(merged_ip_table, remaining);
            size_t best_rid = remaining[best_pos];

            // Get all rules covered by this Rmax
            auto covered_set = get_cover_set(merged_ip_table, best_rid, remaining);

            // Assign Rmax ID to all covered rules
            for (size_t covered_rid : covered_set) {
                Rmax_merged_ip_table[covered_rid].rmax_id = best_rid;
            }
            
            // Mark Rmax as its own leader
            Rmax_merged_ip_table[best_rid].rmax_id = best_rid;

            // Remove processed rules (covered set + Rmax itself) from remaining
            unordered_set<size_t> to_remove(covered_set.begin(), covered_set.end());
            to_remove.insert(best_rid);

            // Update remaining list using erase-remove idiom
            remaining.erase(
                std::remove_if(remaining.begin(), remaining.end(),
                    [&to_remove](size_t rid) { return to_remove.count(rid) > 0; }),
                remaining.end()
            );
        }
    }

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

    // 统计展开后的总表项数
    size_t total_expanded_entries = 0;
    
    // 先计算总数
    for (const auto& r : final_ip_table) {
        auto src_list = range_to_cidrs(r.src_lo, r.src_hi);
        auto dst_list = range_to_cidrs(r.dst_lo, r.dst_hi);
        total_expanded_entries += src_list.size() * dst_list.size();
    }
    
    // 写入列标题（对齐格式）
    fout << std::left
         << std::setw(10) << "Priority"
         << std::setw(20) << "ipv4.src"
         << std::setw(20) << "ipv4.dst"
         << std::setw(12) << "protocol"
         << "GIDs\n";

    size_t entry_count = 0;
    
    for (size_t i = 0; i < final_ip_table.size(); ++i) {
        const auto& r = final_ip_table[i];

        // 生成SRC和DST的CIDR列表
        auto src_list = range_to_cidrs(r.src_lo, r.src_hi);
        auto dst_list = range_to_cidrs(r.dst_lo, r.dst_hi);

        // 笛卡尔积：每个SRC CIDR × 每个DST CIDR = 一条独立表项
        for (const auto& src_cidr : src_list) {
            for (const auto& dst_cidr : dst_list) {
                // 格式化输出：Priority, ipv4.src, ipv4.dst, protocol, GIDs
                fout << std::left
                     << std::setw(10) << entry_count
                     << std::setw(20) << src_cidr
                     << std::setw(20) << dst_cidr
                     << std::setw(12) << static_cast<int>(r.proto);

                // 输出 GIDs（不带花括号，用逗号分隔）
                for (size_t k = 0; k < r.group_ids.size(); ++k) {
                    fout << r.group_ids[k];
                    if (k + 1 < r.group_ids.size()) fout << ", ";
                }

                fout << "\n";

                entry_count++;
            }
        }
    }

    fout.close();
    
    cout << "CIDR-expanded table written to " << filename << endl;
    
}


void Generate_cell_GID_to_metainfo(
    const vector<IntersectionCell>& intersection_cells,
    const vector<IntersectionCell>& Rmax_intersections,
    const vector<IPRule>& merged_ip_table,
    const vector<PortRule>& port_table,
    const vector<FinalIPRule>& final_ip_table,
    vector<Metainfo_for_SRC_port>& meta_src
)
{   
    bool enable_debug = false;

    // ========== 1. 建立 cell 查找表 ==========
    std::unordered_map<std::string, size_t> cell_key_to_index;
    cell_key_to_index.reserve(intersection_cells.size());
    for (size_t ci = 0; ci < intersection_cells.size(); ++ci) {
        const auto &c = intersection_cells[ci];
        std::string key = std::to_string(c.src_lo) + "-" + std::to_string(c.src_hi) + "-" +
                          std::to_string(c.dst_lo) + "-" + std::to_string(c.dst_hi) + "-" +
                          std::to_string((int)c.proto);
        cell_key_to_index.emplace(key, ci);
    }

    // ========== 2. 建立 Rmax_cell 查找表 ==========
    std::unordered_map<std::string, size_t> rmax_key_to_index;
    rmax_key_to_index.reserve(Rmax_intersections.size());
    for (size_t ci = 0; ci < Rmax_intersections.size(); ++ci) {
        const auto &c = Rmax_intersections[ci];
        std::string key = std::to_string(c.src_lo) + "-" + std::to_string(c.src_hi) + "-" +
                          std::to_string(c.dst_lo) + "-" + std::to_string(c.dst_hi) + "-" +
                          std::to_string((int)c.proto);
        rmax_key_to_index.emplace(key, ci);
    }

    // Helper: build key from final rule coords
    auto make_key_from_final = [](const FinalIPRule &fr)->std::string {
        return std::to_string(fr.src_lo) + "-" + std::to_string(fr.src_hi) + "-" +
               std::to_string(fr.dst_lo) + "-" + std::to_string(fr.dst_hi) + "-" +
               std::to_string((int)fr.proto);
    };

    // ========== 3. 遍历 final_ip_table ==========
    for (size_t fi = 0; fi < final_ip_table.size(); ++fi) {
        const FinalIPRule &fr = final_ip_table[fi];
        if (!fr.is_cell) continue;
        if (fr.group_ids.empty()) continue;

        int gid = fr.group_ids[0];
        std::string key = make_key_from_final(fr);

        const IntersectionCell* ic = nullptr;
        bool is_rmax_cell = false;

        // 3.1 先查普通 cell
        auto itc = cell_key_to_index.find(key);
        if (itc != cell_key_to_index.end()) {
            ic = &intersection_cells[itc->second];
        } else {
            // 3.2 再查 Rmax_cell
            auto itr = rmax_key_to_index.find(key);
            if (itr != rmax_key_to_index.end()) {
                ic = &Rmax_intersections[itr->second];
                is_rmax_cell = true;
            }
        }

        if (!ic) {
            if (enable_debug) {
                std::cout << "[WARN] no cell or Rmax_cell found for key=" << key << "\n";
            }
            continue;
        }

        // ========== 4. 展开 Extraction ==========
        for (size_t orig_rid : ic->Extraction) {
            auto it = std::find_if(
                port_table.begin(),
                port_table.end(),
                [orig_rid](const PortRule &pr) {
                    return pr.rid == orig_rid;
                }
            );

            if (it == port_table.end()) continue;

            const PortRule &por = *it;

            Metainfo_for_SRC_port new_entry;
            new_entry.Inital_Number = { static_cast<uint32_t>(orig_rid) };
            new_entry.Src_lo   = por.src_port_lo;
            new_entry.Src_hi   = por.src_port_hi;
            new_entry.Dst_lo   = por.dst_port_lo;
            new_entry.Dst_hi   = por.dst_port_hi;
            new_entry.action   = por.action;
            new_entry.group_ids = { gid };

            meta_src.push_back(new_entry);
        }
    }

    if (enable_debug) {
        std::cout << "[INFO] Generate_cell_GID_to_metainfo done. meta_src size="<< meta_src.size() << "\n";
    }
}


void Generate_MergedR_GID_to_metaifno(
    const vector<FinalIPRule>& final_ip_table,
    const vector<PortRule>& port_table,
    const vector<Rmax_IPRule>& RO_merged_ip_table,
    const std::unordered_map<size_t, size_t>& old_to_new_idx,
    vector<Metainfo_for_SRC_port>& meta_src)
{
    // 辅助函数：添加端口对到 meta_src
    auto add_port_pair = [&](uint32_t gid, size_t orig_rid, 
                             std::set<std::tuple<int, int, int, int>>& seen_in_gid) {
        // 在 port_table 中查找对应的端口规则
        auto it = std::find_if(port_table.begin(), port_table.end(),
            [orig_rid](const PortRule &pr) { return pr.rid == orig_rid; });

        if (it == port_table.end()) {
            return;  // 未找到对应的端口规则，跳过
        }

        const PortRule &por = *it;

        // 在相同 G-ID 内部去重（检查完整的四元组）
        auto dedup_key = std::make_tuple(por.src_port_lo, por.src_port_hi, 
                                         por.dst_port_lo, por.dst_port_hi);
        
        if (seen_in_gid.find(dedup_key) != seen_in_gid.end()) {
            // 已存在相同的端口范围，跳过
            return;
        }
        seen_in_gid.insert(dedup_key);

        // 创建新的 metainfo entry
        Metainfo_for_SRC_port new_entry;
        new_entry.Inital_Number = { static_cast<uint32_t>(orig_rid) };
        new_entry.Src_lo   = por.src_port_lo;
        new_entry.Src_hi   = por.src_port_hi;
        new_entry.Dst_lo   = por.dst_port_lo;
        new_entry.Dst_hi   = por.dst_port_hi;
        new_entry.action   = por.action;
        new_entry.group_ids = { static_cast<int>(gid) };

        meta_src.push_back(new_entry);
    };

    // 遍历 final_ip_table 中的非 cell 规则
    for (const auto& fr : final_ip_table)
    {
        // 🚫 跳过 cell
        if (fr.is_cell) continue;

        if (fr.group_ids.empty()) continue;

        uint32_t gid = fr.group_ids[0];  // 取该规则的 G-ID

        // 用于在相同 G-ID 内部去重（检查 Src_lo, Src_hi, Dst_lo, Dst_hi 是否相同）
        std::set<std::tuple<int, int, int, int>> seen_in_gid;  // (Src_lo, Src_hi, Dst_lo, Dst_hi)

        // ========== 1. 处理规则自己的原始规则 ID ==========
        for (size_t orig_rid : fr.merged_R)
        {
            add_port_pair(gid, orig_rid, seen_in_gid);
        }

        // ========== 2. 处理祖先规则的原始规则 ID ==========
        // fr.original_merged_index 是 RO_merged_ip_table 中的新索引
        if (fr.original_merged_index != SIZE_MAX && 
            fr.original_merged_index < RO_merged_ip_table.size())
        {
            const auto& rmax_rule = RO_merged_ip_table[fr.original_merged_index];
            
            // 遍历祖先（ancestors 存储的是旧索引）
            for (size_t old_ancestor_idx : rmax_rule.ancestors)
            {
                // 将旧索引映射到新索引
                auto it = old_to_new_idx.find(old_ancestor_idx);
                if (it == old_to_new_idx.end()) {
                    continue;  // 找不到映射，跳过
                }
                
                size_t new_ancestor_idx = it->second;
                if (new_ancestor_idx >= RO_merged_ip_table.size()) {
                    continue;  // 索引越界，跳过
                }
                
                // 获取祖先规则的 merged_R
                const auto& ancestor_rule = RO_merged_ip_table[new_ancestor_idx];
                for (size_t ancestor_orig_rid : ancestor_rule.merged_R)
                {
                    add_port_pair(gid, ancestor_orig_rid, seen_in_gid);
                }
            }
        }
    }
}


// 函数1：合并与重排 Metainfo
// 功能：对 metainfo 列表按 GID 排序，合并相同 (GroupIDs, Src_lo, Src_hi) 的条目，并重新分配 ID
void Merge_and_Reorder_Metainfo(
    const vector<Metainfo_for_SRC_port>& meta,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& merged_output)
{
    // DEBUG: 统计空GID条目
    int empty_gid_count = 0;
    int total_count = meta.size();
    for (const auto& m : meta) {
        if (m.group_ids.empty()) {
            empty_gid_count++;
        }
    }

    // Step 1: 过滤掉空 GID 的条目
    std::vector<Metainfo_for_SRC_port> filtered_meta;
    for (const auto& m : meta) {
        if (!m.group_ids.empty()) {
            filtered_meta.push_back(m);
        }
    }

    // Step 2: 按 G-ID 排序 filtered_meta
    std::sort(filtered_meta.begin(), filtered_meta.end(),
        [](const Metainfo_for_SRC_port &a, const Metainfo_for_SRC_port &b) {
            // 现在可以安全地假设 group_ids 非空
            int ga = a.group_ids[0];
            int gb = b.group_ids[0];

            if (ga != gb) return ga < gb;
            if (a.Src_lo != b.Src_lo) return a.Src_lo < b.Src_lo;
            if (a.Src_hi != b.Src_hi) return a.Src_hi < b.Src_hi;
            // 比较 Inital_Number vector（字典序）
            return a.Inital_Number < b.Inital_Number;
        }
    );

    // Step 3: 合并相同 (GroupIDs, Src_lo, Src_hi, Dst_lo, Dst_hi) 的条目
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem> merged_map;

    for (size_t i = 0; i < filtered_meta.size(); ++i) {
        const auto& m = filtered_meta[i];
        auto key = std::make_tuple(m.group_ids, m.Src_lo, m.Src_hi, m.Dst_lo, m.Dst_hi);

        // 如果键不存在，创建新条目
        if (merged_map.find(key) == merged_map.end()) {
            merged_map[key] = {
                m.group_ids,
                m.Src_lo,
                m.Src_hi,
                m.Dst_lo,
                m.Dst_hi,
                {},    // idx_list
                {},    // initnum_list
                m.action
            };
        }

        // 累积 Idx（重排后的行号）和 InitNum
        merged_map[key].idx_list.push_back(i + 1);
        
        // 将 Inital_Number vector 的所有元素追加到 initnum_list（去重）
        for (uint32_t num : m.Inital_Number) {
            if (std::find(merged_map[key].initnum_list.begin(), 
                         merged_map[key].initnum_list.end(), 
                         num) == merged_map[key].initnum_list.end()) {
                merged_map[key].initnum_list.push_back(num);
            }
        }
    }

    // Step 3: 将 map 转换为 vector 并按 GID1 排序
    std::vector<std::pair<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>> merged_vec(
        merged_map.begin(), merged_map.end()
    );
    
    std::sort(merged_vec.begin(), merged_vec.end(),
        [](const auto &a, const auto &b) {
            int gid_a = a.second.group_ids.empty() ? -1 : a.second.group_ids[0];
            int gid_b = b.second.group_ids.empty() ? -1 : b.second.group_ids[0];
            return gid_a < gid_b;
        }
    );

    // Step 4: 重新分配连续的 ID
    int newID = 0;
    for (auto &kv : merged_vec) {
        auto &item = kv.second;
        item.idx_list.clear();
        item.idx_list.push_back(newID);
        newID++;
    }

    // Step 5: 重新构建 merged_output（保持按 GID1 排序的顺序）
    merged_output.clear();
    for (const auto &kv : merged_vec) {
        merged_output[kv.first] = kv.second;
    }
}

// 函数2：输出 Metainfo 到文件
// 功能：将合并后的 metainfo 输出到 meta_merged.txt 文件
void Write_Metainfo_to_File(
    const std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& merged_output,
    const std::string& filename = "src/output/meta_merged.txt")
{
    std::ofstream fout(filename);
    if (!fout) {
        std::cerr << "Error: cannot open " << filename << "\n";
        return;
    }

    // 写入表头
    fout << "GroupIDs\tSrc_lo\tSrc_hi\tDst_lo\tDst_hi\tIdx_list\tInitNum_list\tAction\n";

    // 按顺序输出每一行
    for (const auto& kv : merged_output) {
        const auto& item = kv.second;

        // 格式化 GroupIDs
        std::string group_str = "{";
        for (size_t i = 0; i < item.group_ids.size(); ++i) {
            group_str += std::to_string(item.group_ids[i]);
            if (i + 1 < item.group_ids.size()) group_str += ",";
        }
        group_str += "}";

        // 格式化 Idx_list
        std::string idx_str = "{";
        for (size_t i = 0; i < item.idx_list.size(); ++i) {
            idx_str += std::to_string(item.idx_list[i]);
            if (i + 1 < item.idx_list.size()) idx_str += ",";
        }
        idx_str += "}";

        // 格式化 InitNum_list
        std::string initnum_str = "{";
        for (size_t i = 0; i < item.initnum_list.size(); ++i) {
            initnum_str += std::to_string(item.initnum_list[i]);
            if (i + 1 < item.initnum_list.size()) initnum_str += ",";
        }
        initnum_str += "}";

        // 对齐输出
        fout << std::left
            << std::setw(12) << group_str
            << std::setw(8)  << item.src_lo
            << std::setw(8)  << item.src_hi
            << std::setw(8)  << item.dst_lo
            << std::setw(8)  << item.dst_hi
            << std::setw(18) << idx_str
            << std::setw(20) << initnum_str
            << std::setw(8)  << item.action
            << "\n";
    }

    fout.close();
    std::cout << "[INFO] " << filename << " saved.\n";
}


void Create_Metainfo_for_port(
    const vector<PortRule>& port_table,
    const vector<IPRule>& merged_ip_table,
    const vector<IntersectionCell>& intersections,
    const vector<IntersectionCell>& rmax_intersections,
    const vector<FinalIPRule>& final_ip_table,
    const vector<Rmax_IPRule>& RO_merged_ip_table,
    const std::unordered_map<size_t, size_t>& old_to_new_idx,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& merged_output)
{
    vector<Metainfo_for_SRC_port> meta;

    // 初始化为空，由下面两个函数填充
    meta.clear();
    
    // 为交叉单元生成 GID 映射（创建新的 meta entries）
    Generate_cell_GID_to_metainfo(intersections, rmax_intersections, merged_ip_table, port_table, final_ip_table, meta);
    
    // 为合并规则生成 GID 映射（创建新的 meta entries，包括祖先规则的端口对）
    Generate_MergedR_GID_to_metaifno(final_ip_table, port_table, RO_merged_ip_table, old_to_new_idx, meta);

    // 合并与重排 Metainfo
    Merge_and_Reorder_Metainfo(meta, merged_output);
    
    // 输出 Metainfo 到文件
    Write_Metainfo_to_File(merged_output);
};


static void build_ancestors_for_subset(
    const std::vector<size_t>& rule_indices,
    const std::vector<Rmax_IPRule>& table,
    std::unordered_map<size_t, std::vector<size_t>>& ancestors
)
{
    ancestors.clear();

    // 初始化
    for (size_t rid : rule_indices) {
        ancestors[rid] = {};
    }

    // Step 1: 直接包含关系
    for (size_t a : rule_indices) {
        for (size_t b : rule_indices) {
            if (a == b) continue;

            const auto& A = table[a];
            const auto& B = table[b];

            // A 覆盖 B ⇒ A 是 B 的祖先
            if (A.src_ip_lo <= B.src_ip_lo &&
                A.src_ip_hi >= B.src_ip_hi &&
                A.dst_ip_lo <= B.dst_ip_lo &&
                A.dst_ip_hi >= B.dst_ip_hi)
            {
                ancestors[b].push_back(a);
            }
        }
    }

    // Step 2: 传递闭包（保证 R2 能拿到 R0）
    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& kv : ancestors) {
            size_t node = kv.first;
            auto& vec = kv.second;

            std::vector<size_t> to_add;
            for (size_t p : vec) {
                for (size_t gp : ancestors[p]) {
                    if (gp == node) continue;
                    if (std::find(vec.begin(), vec.end(), gp) == vec.end()) {
                        to_add.push_back(gp);
                    }
                }
            }

            if (!to_add.empty()) {
                vec.insert(vec.end(), to_add.begin(), to_add.end());
                changed = true;
            }
        }
    }
}


void Reorder_merged_ip_table(
    std::vector<Rmax_IPRule>& Rmax_merged_ip_table,
    std::vector<Rmax_IPRule>& RO_merged_ip_table,
    std::unordered_map<size_t, size_t>& old_to_new_idx
)
{
    RO_merged_ip_table.clear();
    old_to_new_idx.clear();
    const size_t N = Rmax_merged_ip_table.size();

    // Step 1: 按 proto 分组
    std::map<uint8_t, std::vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < N; ++i) {
        proto_to_rule_indices[Rmax_merged_ip_table[i].proto].push_back(i);
    }

    // Step 2: 每个 proto 独立：算 ancestors + 排序
    for (auto& kv : proto_to_rule_indices) {
        uint8_t proto = kv.first;
        std::vector<size_t>& rule_indices = kv.second;

        if (rule_indices.size() <= 1) {
            // 单条规则直接写入
            for (size_t rid : rule_indices) {
                size_t new_idx = RO_merged_ip_table.size();
                old_to_new_idx[rid] = new_idx;
                RO_merged_ip_table.push_back(Rmax_merged_ip_table[rid]);
                // 更新 rmax_id：如果是 leader，更新为新索引；否则映射到 leader 的新索引
                size_t old_rmax_id = RO_merged_ip_table[new_idx].rmax_id;
                if (old_rmax_id == rid) {
                    // 这是 leader，更新为新索引
                    RO_merged_ip_table[new_idx].rmax_id = new_idx;
                } else {
                    // 不是 leader，需要找到 leader 的新索引
                    auto it = old_to_new_idx.find(old_rmax_id);
                    if (it != old_to_new_idx.end()) {
                        RO_merged_ip_table[new_idx].rmax_id = it->second;
                    }
                    // 如果找不到，保持原值（理论上不应该发生）
                }
            }
            continue;
        }

        // --------------------------------------------------
        // ★ 核心步骤：在 proto 子集中构建 ancestors
        // --------------------------------------------------
        std::unordered_map<size_t, std::vector<size_t>> ancestors_map;
        build_ancestors_for_subset(
            rule_indices,
            Rmax_merged_ip_table,
            ancestors_map
        );

        // 写回到 Rmax_merged_ip_table
        for (auto& kv2 : ancestors_map) {
            size_t rid = kv2.first;
            Rmax_merged_ip_table[rid].ancestors = kv2.second;
        }

        // --------------------------------------------------
        // Step 3: 重排（祖先多 → 祖先少，即覆盖范围大的在后，优先级低）
        // --------------------------------------------------
        std::vector<size_t> ordered = rule_indices;
        std::sort(
            ordered.begin(),
            ordered.end(),
            [&](size_t a, size_t b) {
                size_t anc_a = Rmax_merged_ip_table[a].ancestors.size();
                size_t anc_b = Rmax_merged_ip_table[b].ancestors.size();
                if (anc_a != anc_b) {
                    return anc_a > anc_b;  // ancestors 多的在前，ancestors 少的在后（大范围规则在后）
                }
                // 如果 ancestors 数量相同，保持原顺序
                return a < b;
            }
        );
        

        // --------------------------------------------------
        // Step 4: 先建立该 proto 组内的索引映射
        // --------------------------------------------------
        std::unordered_map<size_t, size_t> proto_old_to_new;
        size_t base_idx = RO_merged_ip_table.size();
        for (size_t pos = 0; pos < ordered.size(); ++pos) {
            size_t rid = ordered[pos];
            size_t new_idx = base_idx + pos;
            proto_old_to_new[rid] = new_idx;
            old_to_new_idx[rid] = new_idx;
        }

        // --------------------------------------------------
        // Step 5: 写入 RO_merged_ip_table 并更新 rmax_id
        // --------------------------------------------------
        for (size_t rid : ordered) {
            size_t new_idx = proto_old_to_new[rid];
            
            // 复制规则
            RO_merged_ip_table.push_back(Rmax_merged_ip_table[rid]);
            
            // ★ 更新 rmax_id：如果是 leader，设置为新索引；否则映射到 leader 的新索引
            size_t old_rmax_id = RO_merged_ip_table[new_idx].rmax_id;
            if (old_rmax_id == rid) {
                // 这是 leader，更新为新索引
                RO_merged_ip_table[new_idx].rmax_id = new_idx;
            } else {
                // 不是 leader，需要找到 leader 的新索引
                auto it = proto_old_to_new.find(old_rmax_id);
                if (it != proto_old_to_new.end()) {
                    RO_merged_ip_table[new_idx].rmax_id = it->second;
                } else {
                    // leader 不在当前 proto 组（理论上不应该发生，但安全处理）
                    // 保持原值
                }
            }
            // ★ 注意：ancestors 保持为旧索引，不修改
        }
    }
}





#ifdef DEMO_LOADER_MAIN
int main(int argc, char **argv) {
    return 0;
}
#endif /* COMPILE_AS_LIB */
