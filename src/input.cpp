/** *************************************************************/
// @Name: input.cpp
// @Function: Load 5D rules from file, split into IP and Port tables
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-10-30
/************************************************************* */


#include "input.hpp"
#include <bits/stdc++.h>
#include <iostream>
using namespace std;
using u32 = uint32_t;


// 
static std::pair<uint32_t,uint32_t> ip_range_from_parts(unsigned a, unsigned b, unsigned c, unsigned d, unsigned masklen) {
    const uint32_t MAXU = 0xFFFFFFFFu;

    if (masklen == 0) {
        return {0u, MAXU};
    }
    if (masklen > 32) {
        throw std::invalid_argument("masklen > 32");
    }

    // 
    uint32_t base = ( (uint32_t)a << 24 ) | ( (uint32_t)b << 16 ) | ( (uint32_t)c << 8 ) | (uint32_t)d;

    // 计算 mask 和区间
    uint32_t low = 0, high = 0;
    if (masklen == 32) {
        low = base & MAXU;
        high = low;
    } else {
        // 使用 64-bit 中间量，避免对 32-bit 的边界移位未定义/溢出
        uint64_t block = (1ULL << (32 - masklen));         // >=1 且 <= 2^32
        uint64_t low64 = static_cast<uint64_t>(base) & ( (masklen==0) ? 0ULL : ( (~0ULL) << (64 - masklen) ) ); 
        // 上一行为了保险，实际上我们直接用 mask below 更清楚
        uint32_t mask = ~(MAXU >> masklen);
        low = base & mask;
        uint64_t high64 = static_cast<uint64_t>(low) + (block - 1ULL);
        if (high64 > 0xFFFFFFFFULL) high = 0xFFFFFFFFu;
        else high = static_cast<uint32_t>(high64);
    }

    return {low, high};
}


void load_rules_from_file(const string &file, vector<Rule5D> &rules_out) {
    FILE *fp = fopen(file.c_str(), "r");
    if (!fp) {
        fprintf(stderr, "error - cannot open rules file: %s\n", file.c_str());
        exit(1);
    }

    unsigned sip1,sip2,sip3,sip4, smask;
    unsigned dip1,dip2,dip3,dip4, dmask;
    unsigned sport1, sport2, dport1, dport2;
    unsigned protocol, protocol_mask;
    unsigned action_flags, action_mask;

    u32 rule_count = 0;
    // read lines until EOF
    while (true) {
        // note: accept spaces or tabs between fields; use fscanf with format similar to InputFile5D
        int ret = fscanf(fp,
            "@%u.%u.%u.%u/%u %u.%u.%u.%u/%u %u : %u %u : %u %x/%x %x/%x\n",
            &sip1, &sip2, &sip3, &sip4, &smask,
            &dip1, &dip2, &dip3, &dip4, &dmask,
            &sport1, &sport2, &dport1, &dport2,
            &protocol, &protocol_mask,
            &action_flags, &action_mask
        );

        // Sometimes separators are tabs; try alternate format when initial fails
        if (ret == EOF) break;
        if (ret < 14) {
            // try a more tolerant scanf with tabs/colons
            // we'll fallback to reading whole line and parse with sscanf
            char buf[1024];
            if (!fgets(buf, sizeof(buf), fp)) break;
            // attempt sscanf on buf
            ret = sscanf(buf, "@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%u : %u\t%u : %u\t%x/%x\t%x/%x",
                         &sip1,&sip2,&sip3,&sip4,&smask,
                         &dip1,&dip2,&dip3,&dip4,&dmask,
                         &sport1,&sport2,&dport1,&dport2,
                         &protocol,&protocol_mask,
                         &action_flags,&action_mask);
            if (ret < 14) {
                // skip this bad line
                continue;
            }
        }

        Rule5D r;
        // src IP
        auto sr = ip_range_from_parts(sip1,sip2,sip3,sip4, smask);
        r.range[0][0] = sr.first;
        r.range[0][1] = sr.second;
        // dst IP
        auto dr = ip_range_from_parts(dip1,dip2,dip3,dip4, dmask);
        r.range[1][0] = dr.first;
        r.range[1][1] = dr.second;
        // source port
        r.range[2][0] = (u32)sport1;
        r.range[2][1] = (u32)sport2;
        // dest port
        r.range[3][0] = (u32)dport1;
        r.range[3][1] = (u32)dport2;
        // protocol
        if (protocol_mask == 0xFF) {
            r.range[4][0] = (u32)protocol;
            r.range[4][1] = (u32)protocol;
        } else if (protocol_mask == 0x00) {
            r.range[4][0] = 0u;
            r.range[4][1] = 0xFFu;
        } else {
            // if other masks appear, for now treat as full range (or you can refine)
            r.range[4][0] = 0u;
            r.range[4][1] = 0xFFu;
        }

        // prefix_length fields: keep same semantics as original simple loader
        r.prefix_length[0] = (int)smask;
        r.prefix_length[1] = (int)dmask;
        r.prefix_length[2] = (sport1 == sport2) ? 0 : 1;
        r.prefix_length[3] = (dport1 == dport2) ? 0 : 1;
        r.prefix_length[4] = (protocol_mask != 0x00) ? 0 : 1;

        ++rule_count;
        r.priority = rule_count;
        r.action = static_cast<uint16_t>(action_flags);  // 保存 action 值

        rules_out.emplace_back(r);
    }

    fclose(fp);
}


void split_rules(
    const std::vector<Rule5D>& all_rules,
    std::vector<IPRule>& ip_table,
    std::vector<PortRule>& port_table
) {
    ip_table.clear();
    port_table.clear();
    uint32_t i=0;

    for (const auto& r : all_rules) {
        // ---- 构造 IP 表 ----
        IPRule ipr;
        ipr.src_ip_lo = r.range[0][0];
        ipr.src_ip_hi = r.range[0][1];
        ipr.dst_ip_lo = r.range[1][0];
        ipr.dst_ip_hi = r.range[1][1];
        ipr.proto     = static_cast<uint8_t>(r.range[4][0]);
        ipr.priority  = r.priority;
        ipr.src_prefix_len = r.prefix_length[0];  // 传递掩码长度
        ipr.dst_prefix_len = r.prefix_length[1];

        // 计算并保存前缀表示
        // ipr.src_prefix = range_to_cidr(r.range[0][0], r.range[0][1])[0];  // 假设是唯一的CIDR
        // ipr.dst_prefix = range_to_cidr(r.range[1][0], r.range[1][1])[0];  // 假设是唯一的CIDR

        ip_table.push_back(ipr);

        // ---- 构造 Port 表 ----
        PortRule pr;
        pr.rid         = i;
        pr.src_port_lo = static_cast<uint16_t>(r.range[2][0]);
        pr.src_port_hi = static_cast<uint16_t>(r.range[2][1]);
        pr.dst_port_lo = static_cast<uint16_t>(r.range[3][0]);
        pr.dst_port_hi = static_cast<uint16_t>(r.range[3][1]);
        pr.priority    = r.priority;
        pr.action      = r.action;  // 从 Rule5D 传递 action
        port_table.push_back(pr);

        i++; 
    }

    std::cout << "[split_rules] IP table size = " << ip_table.size()
              << ", Port table size = " << port_table.size() << std::endl;
}



static string ip_to_string(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
           
}

vector<string> range_to_cidr(uint32_t start, uint32_t end) {
    vector<string> res;
    while (start <= end) {
        uint32_t max_size = start & -start; 
        uint32_t remaining = end - start + 1;

        // 拿 log2 判断最大可能掩码长
        int prefix = 32;
        while (max_size > 1) {
            max_size >>= 1;
            prefix--;
        }
        while ((1u << (32 - prefix)) > remaining) {
            prefix++;
        }

        res.push_back(ip_to_string(start) + "/" + to_string(prefix));
        start += (1u << (32 - prefix));
    }
    return res;
}


#ifdef DEMO_LOADER_MAIN
int main(int argc, char **argv) {
    string path = "ACL_rules/acl_10k.rules"; // 修改为你实际路径，或使用 argv[1]
    if (argc >= 2) path = argv[1];

    vector<Rule5D> rules;
    load_rules_from_file(path, rules);
    cout << "Loaded rules: " << rules.size() << "\n";

    // print first few rules as check
    for (size_t i = 0; i < min<size_t>(rules.size(), 5); ++i) {
        auto &r = rules[i];
        cout << "Rule " << i+1 << " pri=" << r.priority << "\n";
        cout << "  SRC [" << r.range[0][0] << "," << r.range[0][1] << "]\n";
        cout << "  DST [" << r.range[1][0] << "," << r.range[1][1] << "]\n";
        cout << "  SPORT [" << r.range[2][0] << "," << r.range[2][1] << "]\n";
        cout << "  DPORT [" << r.range[3][0] << "," << r.range[3][1] << "]\n";
        cout << "  PROTO [" << r.range[4][0] << "," << r.range[4][1] << "]\n";
    }
    return 0;
}
#endif
