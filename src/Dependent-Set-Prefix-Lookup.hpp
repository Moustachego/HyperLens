#pragma once  // 或者下面这种传统写法
#include <vector>
using namespace std;

struct IntersectionCell {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;
    size_t   rmax_id;   
    std::vector<size_t> rule_indices; // 记录由哪些规则覆盖（索引为 merged_ip_table 索引）
};

struct FinalIPRule {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;
    uint32_t priority;              // 可以设置为0或原始优先级
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

void merge_same_ip_entry(
    const std::vector<IPRule>& ip_table,
    std::vector<IPRule>& merged_ip_table
);