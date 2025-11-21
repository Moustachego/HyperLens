#pragma once  // 或者下面这种传统写法
#include <vector>
#include <map>
#include <tuple>
#include <algorithm>
#include <fstream>
#include <iostream>
using namespace std;

struct IntersectionCell {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;
    size_t   rmax_id;   
    std::vector<size_t> rule_indices; // 记录由哪些规则覆盖（索引为 merged_ip_table 索引）
    std::vector<size_t> Extraction;
};

struct FinalIPRule {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;
    uint32_t priority;              // 可以设置为0或原始优先级
    uint32_t original_merged_index;
    vector<int> group_ids;          // 自身ID + Rmax的Group_ID
    bool is_cell = false;   // 是否为 intersection cell 产生的规则
    bool is_rmax = false;   // 是否属于 Rmax 区域
    std::vector<size_t> merged_R;
};

struct Rmax_IPRule {
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;
    uint8_t  proto;
    uint32_t priority;
    int src_prefix_len;
    int dst_prefix_len;
    size_t   rmax_id;
    std::vector<size_t> merged_R;  // 存储原始规则的编号
};

struct Metainfo_for_SRC_port{
    uint32_t Inital_Number;
    uint16_t Src_lo;
    uint16_t Src_hi;
    uint16_t Dst_lo;
    uint16_t Dst_hi;
    vector<int> group_ids; 
};

struct MergedItem{
    std::vector<int> group_ids;      // GID 列表（你目前只有 1 个 GID）
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    std::vector<int> idx_list;       // 合并后的多个 Idx（重排后 i+1）
    std::vector<int> initnum_list;   // 合并后的多个 InitNum
};


// ===== Function Declarations =====

void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<IPRule>& merged_ip_table
);

void build_elementary_intervals_per_proto(
    const std::vector<IPRule>& ip_table,
    std::map<uint8_t, std::vector<uint32_t>>& src_intervals_per_proto,
    std::map<uint8_t, std::vector<uint32_t>>& dst_intervals_per_proto
);

void find_intersections_per_proto(
    const std::vector<IPRule>& merged_ip_table,
    const std::map<uint8_t, std::vector<uint32_t>>& src_intervals_per_proto,
    const std::map<uint8_t, std::vector<uint32_t>>& dst_intervals_per_proto,
    std::vector<IntersectionCell>& intersections,
    std::vector<size_t>& rmax_rule_ids
);

void merge_cells_and_ip_table(
    const std::vector<Rmax_IPRule>& Rmax_merged_ip_table,
    const std::vector<IntersectionCell>& intersections,
    std::vector<FinalIPRule>& final_ip_table
);

std::vector<IPRule> split_rule_by_cell(
    const IPRule &rule,
    const IntersectionCell &cell
);

void extract_and_split_cells(
    const std::vector<IPRule> &merged_ip_table,
    const std::vector<IntersectionCell> &intersections,
    std::vector<IPRule> &extra_rules
);

void find_Rmax_for_merged_ip_table(
    const std::vector<IPRule>& merged_ip_table,
    std::vector<Rmax_IPRule>& Rmax_merged_ip_table
);

std::string ip_to_string(uint32_t ip);

std::vector<std::string> range_to_cidrs(uint32_t start, uint32_t end);

void write_final_table_in_cidr(
    const std::vector<FinalIPRule>& final_ip_table,
    const std::string& filename
);

void Create_Metainfo_for_port(
    const vector<PortRule>& port_table,
    const vector<IPRule>& merged_ip_table,
    const vector<IntersectionCell>& IntersectionCell,
    const vector<FinalIPRule>& final_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& merged_output
);