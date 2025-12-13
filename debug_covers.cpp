#include <iostream>
#include <vector>
#include <cstdint>

struct IPRule {
    uint32_t src_ip_lo, src_ip_hi;
    uint32_t dst_ip_lo, dst_ip_hi;
    uint8_t  proto;
    uint32_t priority;
    int src_prefix_len;
    int dst_prefix_len;
    std::vector<size_t> merged_R;  // original rule indices
};

static inline bool covers(const IPRule& A, const IPRule& B) {
    if (&A == &B) return false;
    return (A.src_ip_lo <= B.src_ip_lo &&
            A.src_ip_hi >= B.src_ip_hi &&
            A.dst_ip_lo <= B.dst_ip_lo &&
            A.dst_ip_hi >= B.dst_ip_hi);
}

// Utility to convert IP address to uint32_t
uint32_t ip_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8) |
           static_cast<uint32_t>(d);
}

int main() {
    // 创建测试规则
    // Rule 1: @217.225.115.224/27 192.0.0.0/2
    IPRule rule1;
    rule1.src_ip_lo = ip_to_uint32(217, 225, 115, 224);  // 217.225.115.224
    rule1.src_ip_hi = ip_to_uint32(217, 225, 115, 255);  // 217.225.115.255
    rule1.dst_ip_lo = ip_to_uint32(192, 0, 0, 0);        // 192.0.0.0
    rule1.dst_ip_hi = ip_to_uint32(255, 255, 255, 255);  // 255.255.255.255
    
    // Rule 2: @0.0.0.0/0 195.128.0.0/9
    IPRule rule2;
    rule2.src_ip_lo = ip_to_uint32(0, 0, 0, 0);          // 0.0.0.0
    rule2.src_ip_hi = ip_to_uint32(255, 255, 255, 255);  // 255.255.255.255
    rule2.dst_ip_lo = ip_to_uint32(195, 128, 0, 0);      // 195.128.0.0
    rule2.dst_ip_hi = ip_to_uint32(195, 255, 255, 255);  // 195.255.255.255
    
    std::cout << "规则覆盖测试:\n";
    std::cout << "==================\n";
    
    std::cout << "Rule1 源IP范围: " << rule1.src_ip_lo << " - " << rule1.src_ip_hi << "\n";
    std::cout << "Rule2 源IP范围: " << rule2.src_ip_lo << " - " << rule2.src_ip_hi << "\n";
    std::cout << "Rule1 目标IP范围: " << rule1.dst_ip_lo << " - " << rule1.dst_ip_hi << "\n";
    std::cout << "Rule2 目标IP范围: " << rule2.dst_ip_lo << " - " << rule2.dst_ip_hi << "\n";
    
    std::cout << "\n";
    
    // 测试覆盖关系
    bool rule1_covers_rule2 = covers(rule1, rule2);
    bool rule2_covers_rule1 = covers(rule2, rule1);
    
    std::cout << "Rule1 覆盖 Rule2: " << (rule1_covers_rule2 ? "是" : "否") << "\n";
    std::cout << "Rule2 覆盖 Rule1: " << (rule2_covers_rule1 ? "是" : "否") << "\n";
    
    // 分析原因
    std::cout << "\n分析:\n";
    std::cout << "=====\n";
    std::cout << "Rule1 覆盖 Rule2 需要满足:\n";
    std::cout << "  Rule1.src_lo <= Rule2.src_lo: " << rule1.src_ip_lo << " <= " << rule2.src_ip_lo << " ? " << (rule1.src_ip_lo <= rule2.src_ip_lo ? "是" : "否") << "\n";
    std::cout << "  Rule1.src_hi >= Rule2.src_hi: " << rule1.src_ip_hi << " >= " << rule2.src_ip_hi << " ? " << (rule1.src_ip_hi >= rule2.src_ip_hi ? "是" : "否") << "\n";
    std::cout << "  Rule1.dst_lo <= Rule2.dst_lo: " << rule1.dst_ip_lo << " <= " << rule2.dst_ip_lo << " ? " << (rule1.dst_ip_lo <= rule2.dst_ip_lo ? "是" : "否") << "\n";
    std::cout << "  Rule1.dst_hi >= Rule2.dst_hi: " << rule1.dst_ip_hi << " >= " << rule2.dst_ip_hi << " ? " << (rule1.dst_ip_hi >= rule2.dst_ip_hi ? "是" : "否") << "\n";
    
    std::cout << "\n";
    
    std::cout << "Rule2 覆盖 Rule1 需要满足:\n";
    std::cout << "  Rule2.src_lo <= Rule1.src_lo: " << rule2.src_ip_lo << " <= " << rule1.src_ip_lo << " ? " << (rule2.src_ip_lo <= rule1.src_ip_lo ? "是" : "否") << "\n";
    std::cout << "  Rule2.src_hi >= Rule1.src_hi: " << rule2.src_ip_hi << " >= " << rule1.src_ip_hi << " ? " << (rule2.src_ip_hi >= rule1.src_ip_hi ? "是" : "否") << "\n";
    std::cout << "  Rule2.dst_lo <= Rule1.dst_lo: " << rule2.dst_ip_lo << " <= " << rule1.dst_ip_lo << " ? " << (rule2.dst_ip_lo <= rule1.dst_ip_lo ? "是" : "否") << "\n";
    std::cout << "  Rule2.dst_hi >= Rule1.dst_hi: " << rule2.dst_ip_hi << " >= " << rule1.dst_ip_hi << " ? " << (rule2.dst_ip_hi >= rule1.dst_ip_hi ? "是" : "否") << "\n";
    
    return 0;
}