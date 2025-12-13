#!/usr/bin/env python3

import ipaddress

def visualize_rules():
    # 定义规则
    rules = [
        {
            "name": "Rule 1",
            "src": "217.225.115.224/27",
            "dst": "192.0.0.0/2"
        },
        {
            "name": "Rule 2",
            "src": "0.0.0.0/0",
            "dst": "195.128.0.0/9"
        },
        {
            "name": "Rule 3",
            "src": "0.0.0.0/0",
            "dst": "195.128.0.0/9"
        }
    ]
    
    print("规则IP范围分析:")
    print("=" * 60)
    
    rule_ranges = []
    for i, rule in enumerate(rules, 1):
        src_net = ipaddress.ip_network(rule["src"], strict=False)
        dst_net = ipaddress.ip_network(rule["dst"], strict=False)
        
        print(f"{rule['name']}:")
        print(f"  源IP范围: {src_net}")
        print(f"    起始IP: {src_net.network_address}")
        print(f"    结束IP: {src_net.broadcast_address}")
        print(f"    地址数量: {src_net.num_addresses}")
        print(f"  目标IP范围: {dst_net}")
        print(f"    起始IP: {dst_net.network_address}")
        print(f"    结束IP: {dst_net.broadcast_address}")
        print(f"    地址数量: {dst_net.num_addresses}")
        print()
        
        rule_ranges.append({
            "name": rule["name"],
            "src_network": src_net,
            "dst_network": dst_net
        })
    
    # 检查相交关系
    print("相交关系分析:")
    print("=" * 60)
    
    for i in range(len(rule_ranges)):
        for j in range(i+1, len(rule_ranges)):
            rule1 = rule_ranges[i]
            rule2 = rule_ranges[j]
            
            # 检查源IP是否有交集 (使用overlaps方法)
            src_overlap = rule1["src_network"].overlaps(rule2["src_network"])
            
            # 检查目标IP是否有交集 (使用overlaps方法)
            dst_overlap = rule1["dst_network"].overlaps(rule2["dst_network"])
            
            print(f"{rule1['name']} 与 {rule2['name']} 的相交情况:")
            print(f"  源IP相交: {'是' if src_overlap else '否'}")
            print(f"  目标IP相交: {'是' if dst_overlap else '否'}")
            
            # 如果源和目标都有交集，则规则整体有交集
            if src_overlap and dst_overlap:
                print(f"  结论: 规则整体存在相交区域")
                
                # 计算相交区域
                # 源IP交集
                try:
                    src_intersection = rule1["src_network"].subnet_of(rule2["src_network"])
                    if src_intersection:
                        src_result = f"{rule1['src_network']} 是 {rule2['src_network']} 的子网"
                    else:
                        src_intersection = rule2["src_network"].subnet_of(rule1["src_network"])
                        if src_intersection:
                            src_result = f"{rule2['src_network']} 是 {rule1['src_network']} 的子网"
                        else:
                            # 计算实际交集
                            src_nets = [rule1["src_network"], rule2["src_network"]]
                            # 简单处理：显示较小的网络
                            src_result = str(min(src_nets, key=lambda x: x.num_addresses))
                except:
                    src_result = "复杂交集"
                
                # 目标IP交集
                try:
                    dst_intersection = rule1["dst_network"].subnet_of(rule2["dst_network"])
                    if dst_intersection:
                        dst_result = f"{rule1['dst_network']} 是 {rule2['dst_network']} 的子网"
                    else:
                        dst_intersection = rule2["dst_network"].subnet_of(rule1["dst_network"])
                        if dst_intersection:
                            dst_result = f"{rule2['dst_network']} 是 {rule1['dst_network']} 的子网"
                        else:
                            # 计算实际交集
                            dst_nets = [rule1["dst_network"], rule2["dst_network"]]
                            # 简单处理：显示较小的网络
                            dst_result = str(min(dst_nets, key=lambda x: x.num_addresses))
                except:
                    dst_result = "复杂交集"
                
                print(f"  源IP相交情况: {src_result}")
                print(f"  目标IP相交情况: {dst_result}")
            else:
                print(f"  结论: 规则整体无相交区域")
            print()

if __name__ == "__main__":
    visualize_rules()