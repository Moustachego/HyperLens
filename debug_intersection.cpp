#include <iostream>
#include <vector>
#include <map>
#include <set>
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

static inline size_t find_best_cover_rule_in_set(
    const std::vector<IPRule>& ip_table,
    const std::vector<size_t>& remaining_rules)
{
    size_t best_pos = 0;
    size_t best_count = 0;
    for (size_t p = 0; p < remaining_rules.size(); ++p) {
        size_t ridA = remaining_rules[p];
        const auto &A = ip_table[ridA];
        size_t cnt = 0;
        for (size_t q = 0; q < remaining_rules.size(); ++q) {
            size_t ridB = remaining_rules[q];
            if (covers(A, ip_table[ridB])) ++cnt;
        }
        if (cnt > best_count) {
            best_count = cnt;
            best_pos = p;
        }
        if (cnt == remaining_rules.size()) {
            return p;
        }
    }
    return best_pos;
}

// Utility to convert IP address to uint32_t
uint32_t ip_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (static_cast<uint32_t>(a) << 24) |
           (static_cast<uint32_t>(b) << 16) |
           (static_cast<uint32_t>(c) << 8) |
           static_cast<uint32_t>(d);
}

static inline std::vector<size_t> compute_covered_set(
    const IPRule& Rmax,
    const std::vector<size_t>& remaining,
    const std::vector<IPRule>& merged_ip_table)
{
    std::vector<size_t> S;
    S.reserve(remaining.size());
    
    for (size_t rid : remaining) {
        if (covers(Rmax, merged_ip_table[rid])) {
            S.push_back(rid);
        }
    }
    return S;
}

int main() {
    // 创建测试规则
    std::vector<IPRule> rules(3);
    
    // Rule 1: @217.225.115.224/27 192.0.0.0/2
    rules[0].src_ip_lo = ip_to_uint32(217, 225, 115, 224);  // 217.225.115.224
    rules[0].src_ip_hi = ip_to_uint32(217, 225, 115, 255);  // 217.225.115.255
    rules[0].dst_ip_lo = ip_to_uint32(192, 0, 0, 0);        // 192.0.0.0
    rules[0].dst_ip_hi = ip_to_uint32(255, 255, 255, 255);  // 255.255.255.255
    rules[0].proto = 6; // TCP
    rules[0].merged_R = {0};
    
    // Rule 2: @0.0.0.0/0 195.128.0.0/9
    rules[1].src_ip_lo = ip_to_uint32(0, 0, 0, 0);          // 0.0.0.0
    rules[1].src_ip_hi = ip_to_uint32(255, 255, 255, 255);  // 255.255.255.255
    rules[1].dst_ip_lo = ip_to_uint32(195, 128, 0, 0);      // 195.128.0.0
    rules[1].dst_ip_hi = ip_to_uint32(195, 255, 255, 255);  // 195.255.255.255
    rules[1].proto = 6; // TCP
    rules[1].merged_R = {1};
    
    // Rule 3: @0.0.0.0/0 195.128.0.0/9
    rules[2].src_ip_lo = ip_to_uint32(0, 0, 0, 0);          // 0.0.0.0
    rules[2].src_ip_hi = ip_to_uint32(255, 255, 255, 255);  // 255.255.255.255
    rules[2].dst_ip_lo = ip_to_uint32(195, 128, 0, 0);      // 195.128.0.0
    rules[2].dst_ip_hi = ip_to_uint32(195, 255, 255, 255);  // 195.255.255.255
    rules[2].proto = 6; // TCP
    rules[2].merged_R = {2};
    
    std::cout << "模拟交叉检测过程:\n";
    std::cout << "==================\n";
    
    // 按协议分组
    std::map<uint8_t, std::vector<size_t>> proto_to_rule_indices;
    for (size_t i = 0; i < rules.size(); ++i) {
        proto_to_rule_indices[rules[i].proto].push_back(i);
    }
    
    std::cout << "按协议分组:\n";
    for (const auto& pair : proto_to_rule_indices) {
        std::cout << "协议 " << (int)pair.first << " 包含规则索引: ";
        for (size_t idx : pair.second) {
            std::cout << idx << " ";
        }
        std::cout << "\n";
    }
    
    // 处理每个协议
    for (const auto& [proto, initial_remaining] : proto_to_rule_indices) {
        std::cout << "\n处理协议 " << (int)proto << ":\n";
        std::cout << "初始规则数量: " << initial_remaining.size() << "\n";
        
        if (initial_remaining.size() < 2) {
            std::cout << "规则数量不足2个，跳过处理\n";
            continue;
        }
        
        std::vector<size_t> remaining = initial_remaining;
        
        // 查找最佳覆盖规则(Rmax)
        while (remaining.size() >= 2) {
            size_t best_pos = find_best_cover_rule_in_set(rules, remaining);
            size_t best_rid = remaining[best_pos];
            const auto& Rmax = rules[best_rid];
            
            std::cout << "\n选择Rmax规则: " << best_rid << "\n";
            
            // 计算被Rmax覆盖的规则集合
            std::vector<size_t> S = compute_covered_set(Rmax, remaining, rules);
            
            std::cout << "被Rmax规则 " << best_rid << " 覆盖的规则数量: " << S.size() << "\n";
            std::cout << "覆盖的规则索引: ";
            for (size_t rid : S) {
                std::cout << rid << " ";
            }
            std::cout << "\n";
            
            if (S.size() < 2) {
                std::cout << "覆盖的规则数量不足2个，跳过交叉检测\n";
                remaining.erase(remaining.begin() + best_pos);
                continue;
            }
            
            std::cout << "有足够的规则进行交叉检测\n";
            // 正常情况下会在这里进行交叉检测...
            break;
        }
    }
    
    return 0;
}