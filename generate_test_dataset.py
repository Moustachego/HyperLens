#!/usr/bin/env python3
"""
ACL规则测试集生成器
作用：从ACL规则文件中读取规则，为每条规则生成具体的测试用例
生成策略：
  - 优先改变IP地址（在掩码范围内生成不同IP）
  - 端口随机选择范围内的值
  - 每条规则尝试生成10个测试用例（如果掩码空间不够则生成所有可能的组合）

作者: HyperLens Project
日期: 2025-12-08
"""

import re
import random
import ipaddress
from typing import List, Tuple
import argparse
import os


class ACLRule:
    """ACL规则数据结构"""
    def __init__(self, line: str):
        # 解析规则格式: @src_ip/prefix dst_ip/prefix src_port:src_port dst_port:dst_port proto/mask action/mask
        # 规则文件使用制表符分隔主要字段，但端口字段内部可能有空格（如 "162 : 162"）
        # 去掉注释
        line = line.split('//', 1)[0].strip()

        # 先按制表符分割主要字段（因为规则文件使用制表符分隔）
        # 如果制表符分割后字段数不够，再尝试按任意空格分割
        if '\t' in line:
            parts = line.split('\t')
            # 过滤空字符串
            parts = [p.strip() for p in parts if p.strip()]
        else:
            # 如果没有制表符，按任意空格分割（因为字段之间可能只有单个空格）
            parts = re.split(r'\s+', line)
            # 过滤空字符串
            parts = [p for p in parts if p]
        
        # 源IP和掩码 (去除开头的@)
        src_ip_full = parts[0].lstrip('@')
        src_ip_parts = src_ip_full.split('/')
        if len(src_ip_parts) != 2:
            raise ValueError(f"源IP格式错误: {src_ip_full}")
        self.src_ip = src_ip_parts[0]
        self.src_prefix = int(src_ip_parts[1])
        
        # 目的IP和掩码
        dst_ip_full = parts[1]
        dst_ip_parts = dst_ip_full.split('/')
        if len(dst_ip_parts) != 2:
            raise ValueError(f"目的IP格式错误: {dst_ip_full}")
        self.dst_ip = dst_ip_parts[0]
        self.dst_prefix = int(dst_ip_parts[1])
        
        # 源端口范围处理：端口范围可能被制表符分隔（如 "0	:	65535"）
        # 需要找到完整的端口范围：开始数字、冒号、结束数字
        src_port_start_idx = 2
        src_port_end_idx = src_port_start_idx
        
        # 查找源端口范围的结束位置：需要找到冒号和结束数字
        found_colon = False
        for i in range(src_port_start_idx, len(parts)):
            if ':' in parts[i]:
                found_colon = True
            elif found_colon and parts[i].isdigit():
                # 找到了冒号后的数字，这就是结束位置
                src_port_end_idx = i
                break
        else:
            # 如果没找到完整的范围，尝试合并接下来的几个字段
            if src_port_start_idx + 2 < len(parts):
                src_port_end_idx = src_port_start_idx + 2
        
        # 合并源端口范围字段
        src_port_str = ''.join(parts[src_port_start_idx:src_port_end_idx+1]).replace(' ', '')
        src_port_parts = src_port_str.split(':')
        if len(src_port_parts) != 2 or not src_port_parts[0] or not src_port_parts[1]:
            raise ValueError(f"源端口格式错误: {parts[src_port_start_idx:src_port_end_idx+1]} (处理后: {src_port_str})")
        self.src_port_lo = int(src_port_parts[0])
        self.src_port_hi = int(src_port_parts[1])
        
        # 目的端口范围处理：类似源端口
        dst_port_start_idx = src_port_end_idx + 1
        dst_port_end_idx = dst_port_start_idx
        
        found_colon = False
        for i in range(dst_port_start_idx, len(parts)):
            if ':' in parts[i]:
                found_colon = True
            elif found_colon and parts[i].isdigit():
                dst_port_end_idx = i
                break
        else:
            if dst_port_start_idx + 2 < len(parts):
                dst_port_end_idx = dst_port_start_idx + 2
        
        # 合并目的端口范围字段
        dst_port_str = ''.join(parts[dst_port_start_idx:dst_port_end_idx+1]).replace(' ', '')
        dst_port_parts = dst_port_str.split(':')
        if len(dst_port_parts) != 2 or not dst_port_parts[0] or not dst_port_parts[1]:
            raise ValueError(f"目的端口格式错误: {parts[dst_port_start_idx:dst_port_end_idx+1]} (处理后: {dst_port_str})")
        self.dst_port_lo = int(dst_port_parts[0])
        self.dst_port_hi = int(dst_port_parts[1])
        
        # 协议和Action字段：从目的端口范围之后开始
        proto_idx = dst_port_end_idx + 1
        action_idx = proto_idx + 1
        
        if proto_idx >= len(parts):
            raise ValueError(f"规则字段数不足: 缺少协议字段")
        if action_idx >= len(parts):
            raise ValueError(f"规则字段数不足: 缺少Action字段")
        
        # 协议 (格式: "0x06/0xFF")
        proto_parts = parts[proto_idx].split('/')
        if len(proto_parts) < 1:
            raise ValueError(f"协议格式错误: {parts[proto_idx]}")
        self.proto = int(proto_parts[0], 16)  # 十六进制转换
        
        # Action (格式: "0x1000/0x1000")
        action_parts = parts[action_idx].split('/')
        self.action = action_parts[0]


def generate_ips_in_subnet(network_str: str, prefix_len: int, max_count: int = 10) -> List[str]:
    """
    在给定的网络范围内生成IP地址
    
    Args:
        network_str: 基础IP地址
        prefix_len: 前缀长度
        max_count: 最多生成的IP数量
    
    Returns:
        生成的IP地址列表
    """
    try:
        # 创建网络对象
        network = ipaddress.ip_network(f"{network_str}/{prefix_len}", strict=False)
        
        # 计算该网络中可用的IP数量
        total_ips = network.num_addresses
        
        # 如果是/32单个IP，直接返回
        if prefix_len == 32:
            return [network_str]
        
        # 如果总IP数很少（<=max_count），返回所有
        if total_ips <= max_count:
            # 使用列表推导式而不是 network.hosts()，因为hosts()会跳过网络地址和广播地址
            # 对于小网络，我们包括所有地址
            return [str(network.network_address + i) for i in range(min(total_ips, max_count))]
        
        # 对于大网络，随机采样（使用网络地址的整数值进行高效采样）
        network_int = int(network.network_address)
        sampled_offsets = random.sample(range(1, total_ips - 1), min(max_count, total_ips - 2))
        return [str(ipaddress.ip_address(network_int + offset)) for offset in sampled_offsets]
    
    except Exception as e:
        print(f"Warning: Failed to generate IPs for {network_str}/{prefix_len}: {e}")
        return [network_str]  # 降级返回原始IP


def generate_test_cases_for_rule(rule: ACLRule, rule_idx: int, max_cases: int = 10) -> List[Tuple]:
    """
    为单条规则生成测试用例
    
    Args:
        rule: ACL规则对象
        rule_idx: 规则在原始文件中的索引（从0开始）
        max_cases: 最多生成的测试用例数
    
    Returns:
        测试用例列表，每个元素为 (src_ip, dst_ip, src_port, dst_port, proto, rule_idx)
    """
    test_cases = []
    
    # 生成源IP地址列表
    src_ips = generate_ips_in_subnet(rule.src_ip, rule.src_prefix, max_cases)
    
    # 生成目的IP地址列表
    dst_ips = generate_ips_in_subnet(rule.dst_ip, rule.dst_prefix, max_cases)
    
    # 生成测试用例
    # 策略：优先变化IP地址，端口随机选择
    cases_to_generate = min(max_cases, len(src_ips) * len(dst_ips))
    
    # 如果IP组合足够多，随机选择组合
    if len(src_ips) * len(dst_ips) >= max_cases:
        for i in range(max_cases):
            src_ip = random.choice(src_ips)
            dst_ip = random.choice(dst_ips)
            
            # 端口随机选择
            src_port = random.randint(rule.src_port_lo, rule.src_port_hi)
            dst_port = random.randint(rule.dst_port_lo, rule.dst_port_hi)
            
            test_cases.append((src_ip, dst_ip, src_port, dst_port, rule.proto, rule_idx))
    else:
        # IP组合不够，遍历所有组合
        for src_ip in src_ips:
            for dst_ip in dst_ips:
                src_port = random.randint(rule.src_port_lo, rule.src_port_hi)
                dst_port = random.randint(rule.dst_port_lo, rule.dst_port_hi)
                
                test_cases.append((src_ip, dst_ip, src_port, dst_port, rule.proto, rule_idx))
                
                if len(test_cases) >= max_cases:
                    break
            if len(test_cases) >= max_cases:
                break
    
    return test_cases


def load_acl_rules(rules_file: str) -> List[ACLRule]:
    """从文件加载ACL规则"""
    rules = []
    
    with open(rules_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            try:
                rule = ACLRule(line)
                rules.append(rule)
            except Exception as e:
                print(f"Warning: Failed to parse line {line_num}: {e}")
                continue
    
    return rules


def generate_test_dataset(rules_file: str, output_file: str, cases_per_rule: int = 10):
    """
    生成测试数据集主函数
    
    Args:
        rules_file: ACL规则文件路径
        output_file: 输出测试集文件路径
        cases_per_rule: 每条规则生成的测试用例数
    """
    print("=" * 80)
    print("ACL规则测试集生成器")
    print("=" * 80)
    print(f"输入规则文件: {rules_file}")
    print(f"输出测试集文件: {output_file}")
    print(f"每条规则生成用例数: {cases_per_rule}")
    print()
    
    # 加载规则
    print("[1/3] 加载ACL规则...")
    rules = load_acl_rules(rules_file)
    print(f"✓ 成功加载 {len(rules)} 条规则")
    print()
    
    # 生成测试用例
    print("[2/3] 生成测试用例...")
    all_test_cases = []
    
    for idx, rule in enumerate(rules):
        test_cases = generate_test_cases_for_rule(rule, idx, cases_per_rule)
        all_test_cases.extend(test_cases)
        
        # 更频繁地显示进度
        if (idx + 1) % 500 == 0 or (idx + 1) == len(rules):
            print(f"  处理进度: {idx + 1}/{len(rules)} 规则 ({100*(idx + 1)//len(rules)}%)...")
    
    print(f"✓ 共生成 {len(all_test_cases)} 个测试用例")
    print()
    
    # 写入文件
    print("[3/3] 保存测试集...")
    with open(output_file, 'w') as f:
        # 写入表头
        f.write("# HyperLens ACL规则测试数据集\n")
        f.write(f"# 来源规则文件: {os.path.basename(rules_file)}\n")
        f.write(f"# 生成时间: 2025-12-08\n")
        f.write(f"# 总测试用例数: {len(all_test_cases)}\n")
        f.write("#\n")
        f.write("# 格式: SrcIP  DstIP  SrcPort  DstPort  Protocol  //R<规则编号>\n")
        f.write("# 规则编号从0开始，对应原始ACL规则文件中的第N条规则\n")
        f.write("# " + "=" * 70 + "\n\n")
        
        # 写入测试用例
        for src_ip, dst_ip, src_port, dst_port, proto, rule_idx in all_test_cases:
            f.write(f"{src_ip}\t{dst_ip}\t{src_port}\t{dst_port}\t{proto}\t//R{rule_idx}\n")
    
    print(f"✓ 测试集已保存至: {output_file}")
    print()
    print("=" * 80)
    print("生成完成！")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description='ACL规则测试集生成器 - 为每条规则生成具体的测试用例',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  # 使用默认参数（每条规则10个测试用例）
  python3 generate_test_dataset.py src/ACL_rules/acl1/acl1_50k_16_0.5.rules
  
  # 指定输出文件和用例数
  python3 generate_test_dataset.py src/ACL_rules/acl1/acl1_50k_16_0.5.rules -o my_test.txt -n 20
  
  # 少量测试（每条规则5个用例）
  python3 generate_test_dataset.py src/ACL_rules/test.rules -n 5
        """
    )
    
    parser.add_argument('rules_file', 
                        help='ACL规则文件路径（如: src/ACL_rules/test-rules/Region_test.rules）')
    parser.add_argument('-o', '--output', 
                        default=None,
                        help='输出测试集文件路径（默认: <规则文件名>_testset.txt）')
    parser.add_argument('-n', '--num-cases', 
                        type=int, 
                        default=10,
                        help='每条规则生成的测试用例数（默认: 10）')
    
    args = parser.parse_args()
    
    # 确定输出文件名
    if args.output is None:
        base_name = os.path.splitext(os.path.basename(args.rules_file))[0]
        output_file = f"src/output/{base_name}_testset.txt"
    else:
        output_file = args.output
    
    # 确保输出目录存在
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 生成测试集
    generate_test_dataset(args.rules_file, output_file, args.num_cases)


if __name__ == "__main__":
    main()
