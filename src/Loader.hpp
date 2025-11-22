#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

struct Rule5D {
    // range[d][0] = low, range[d][1] = high
    // 70.240.214.136/24 ,low =70.240.214.0, high= 70.240.214.255
    std::array<std::array<uint32_t,2>, 5> range; 
    std::array<int,5> prefix_length;  // store prefix-like info (as in original)
    uint32_t priority;
    uint16_t action;  // 规则最后一列的 action 值（如 0x0000）
};

struct IPRule {
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;
    uint8_t  proto;
    uint32_t priority;
    int src_prefix_len;
    int dst_prefix_len;
    std::vector<size_t> merged_R;  // 存储原始规则的编号
};

struct PortRule {
    uint32_t rid;
    uint16_t src_port_lo, src_port_hi;
    uint16_t dst_port_lo, dst_port_hi;
    uint32_t priority;
    uint16_t action;  // 从规则最后一列传递的 action 值
};

// ===== API：从文件中加载 ACL 规则到 Rule5D 向量 =====
void load_rules_from_file(
    const std::string &file,
    std::vector<Rule5D> &rules_out
);

void split_rules(
    const std::vector<Rule5D>& all_rules,
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table
);

std::vector<std::string> range_to_cidr(uint32_t start, uint32_t end);