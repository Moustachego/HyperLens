#!/usr/bin/env python3
"""
分析 merged_ip_table 中规则之间的相交/包含关系
用于验证 HyperLens 算法的正确性

用法:
  python3 analyze_intersections.py                    # 分析并输出报告
  python3 analyze_intersections.py --visualize       # 分析 + 可视化随机抽样
  python3 analyze_intersections.py --visualize 5     # 可视化 5 对
"""

import sys
import random
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Dict, Set
import json

@dataclass
class IPRule:
    index: int
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    proto: int
    priority: int
    original_rules: List[int]

def ip_to_int(ip_str: str) -> int:
    """将 IP 字符串转换为整数"""
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def int_to_ip(ip_int: int) -> str:
    """将整数转换为 IP 字符串"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def load_merged_ip_table(filename: str) -> List[IPRule]:
    """加载 merged_ip_table.txt"""
    rules = []
    with open(filename, 'r') as f:
        header = f.readline()  # Skip header
        for line in f:
            parts = line.strip().split('\t')
            if len(parts) < 8:
                continue
            
            idx = int(parts[0])
            src_lo = ip_to_int(parts[1])
            src_hi = ip_to_int(parts[2])
            dst_lo = ip_to_int(parts[3])
            dst_hi = ip_to_int(parts[4])
            proto = int(parts[5])
            priority = int(parts[6])
            original_rules = [int(x) for x in parts[7].split(',')] if parts[7] else []
            
            rules.append(IPRule(idx, src_lo, src_hi, dst_lo, dst_hi, proto, priority, original_rules))
    
    return rules

def range_relation(a_lo: int, a_hi: int, b_lo: int, b_hi: int) -> str:
    """
    判断一维区间 [a_lo, a_hi] 和 [b_lo, b_hi] 的关系
    返回: DISJOINT, EQUAL, A_SUBSET_B, B_SUBSET_A, INTERSECT
    """
    # 不相交
    if a_hi < b_lo or b_hi < a_lo:
        return "DISJOINT"
    
    # 相等
    if a_lo == b_lo and a_hi == b_hi:
        return "EQUAL"
    
    # A 被 B 包含
    if b_lo <= a_lo and a_hi <= b_hi:
        return "A_SUBSET_B"
    
    # B 被 A 包含
    if a_lo <= b_lo and b_hi <= a_hi:
        return "B_SUBSET_A"
    
    # 部分相交
    return "INTERSECT"

def rule_relation(r1: IPRule, r2: IPRule) -> Tuple[str, Dict]:
    """
    分析两条规则的关系
    返回: (关系类型, 相交区域信息)
    """
    # 协议不同，不相交
    if r1.proto != r2.proto:
        return ("DISJOINT", {})
    
    src_rel = range_relation(r1.src_lo, r1.src_hi, r2.src_lo, r2.src_hi)
    dst_rel = range_relation(r1.dst_lo, r1.dst_hi, r2.dst_lo, r2.dst_hi)
    
    # 任一维度不相交，整体不相交
    if src_rel == "DISJOINT" or dst_rel == "DISJOINT":
        return ("DISJOINT", {})
    
    # 计算相交区域
    intersect_src_lo = max(r1.src_lo, r2.src_lo)
    intersect_src_hi = min(r1.src_hi, r2.src_hi)
    intersect_dst_lo = max(r1.dst_lo, r2.dst_lo)
    intersect_dst_hi = min(r1.dst_hi, r2.dst_hi)
    
    intersect_info = {
        "src_lo": int_to_ip(intersect_src_lo),
        "src_hi": int_to_ip(intersect_src_hi),
        "dst_lo": int_to_ip(intersect_dst_lo),
        "dst_hi": int_to_ip(intersect_dst_hi),
        "proto": r1.proto
    }
    
    # 两个维度都相等
    if src_rel == "EQUAL" and dst_rel == "EQUAL":
        return ("EQUAL", intersect_info)
    
    # R1 完全被 R2 包含
    if src_rel in ("EQUAL", "A_SUBSET_B") and dst_rel in ("EQUAL", "A_SUBSET_B"):
        return ("R1_SUBSET_R2", intersect_info)
    
    # R2 完全被 R1 包含
    if src_rel in ("EQUAL", "B_SUBSET_A") and dst_rel in ("EQUAL", "B_SUBSET_A"):
        return ("R2_SUBSET_R1", intersect_info)
    
    # 部分相交（会产生 intersection cell）
    return ("PARTIAL_INTERSECT", intersect_info)

def covers(rmax: IPRule, rule: IPRule) -> bool:
    """
    判断Rmax是否覆盖rule
    """
    # 协议必须相同
    if rmax.proto != rule.proto:
        return False
        
    # 源IP和目标IP都需要被覆盖
    src_covered = rmax.src_lo <= rule.src_lo and rule.src_hi <= rmax.src_hi
    dst_covered = rmax.dst_lo <= rule.dst_lo and rule.dst_hi <= rmax.dst_hi
    
    return src_covered and dst_covered

def find_rmax_for_rules(rules: List[IPRule]) -> Dict[int, int]:
    """
    为每个规则找到对应的Rmax
    返回: 字典 {规则索引: Rmax索引}
    """
    # 按协议分组
    rules_by_proto = defaultdict(list)
    for r in rules:
        rules_by_proto[r.proto].append(r)
    
    rule_to_rmax = {}
    
    # 对每个协议单独处理
    for proto, proto_rules in rules_by_proto.items():
        if len(proto_rules) < 2:
            # 只有一个规则，它本身就是Rmax
            for rule in proto_rules:
                rule_to_rmax[rule.index] = rule.index
            continue
            
        remaining = list(proto_rules)
        
        # 迭代处理直到所有规则都被分配
        while len(remaining) >= 2:
            # 找到最佳覆盖规则（Rmax）
            best_rule = None
            best_area = -1
            
            for rule in remaining:
                area = (rule.src_hi - rule.src_lo + 1) * (rule.dst_hi - rule.dst_lo + 1)
                if area > best_area:
                    best_area = area
                    best_rule = rule
            
            # 找到被这个Rmax覆盖的所有规则
            covered = [r for r in remaining if covers(best_rule, r)]
            
            # 为所有被覆盖的规则分配这个Rmax
            for rule in covered:
                rule_to_rmax[rule.index] = best_rule.index
                
            # 从剩余列表中移除已处理的规则
            remaining = [r for r in remaining if r not in covered]
        
        # 处理剩余的单个规则
        for rule in remaining:
            rule_to_rmax[rule.index] = rule.index
    
    return rule_to_rmax

def group_rules_by_rmax(rules: List[IPRule], rule_to_rmax: Dict[int, int]) -> Dict[int, List[IPRule]]:
    """
    根据Rmax对规则进行分组
    """
    rmax_groups = defaultdict(list)
    for rule in rules:
        rmax_id = rule_to_rmax.get(rule.index, rule.index)
        rmax_groups[rmax_id].append(rule)
    return rmax_groups

def analyze_intersections_by_rmax(rules: List[IPRule]) -> Dict:
    """
    按Rmax分组分析规则间的相交关系
    """
    # 为每个规则找到对应的Rmax
    rule_to_rmax = find_rmax_for_rules(rules)
    
    # 按Rmax分组规则
    rmax_groups = group_rules_by_rmax(rules, rule_to_rmax)
    
    # 按协议分组Rmax
    rmax_by_proto = defaultdict(list)
    rmax_rules_dict = {rule.index: rule for rule in rules}
    for rmax_id in rmax_groups.keys():
        if rmax_id in rmax_rules_dict:
            rmax_rule = rmax_rules_dict[rmax_id]
            rmax_by_proto[rmax_rule.proto].append(rmax_id)
    
    results = {
        "summary": {
            "total_rules": len(rules),
            "total_rmax": len(rmax_groups),
            "rules_by_proto": {},
            "rmax_by_proto": {proto: len(rmax_list) for proto, rmax_list in rmax_by_proto.items()},
            "total_pairs_checked": 0,
            "disjoint_pairs": 0,
            "equal_pairs": 0,
            "subset_pairs": 0,
            "partial_intersect_pairs": 0,
            "cross_rmax_intersections": 0
        },
        "rmax_details": {},  # 每个Rmax的详细信息
        "partial_intersections": [],  # 部分相交信息
        "subset_relations": [],  # 包含关系
        "cross_rmax_intersections": []  # 跨Rmax相交
    }
    
    # 统计各协议规则数
    rules_by_proto = defaultdict(int)
    for rule in rules:
        rules_by_proto[rule.proto] += 1
    results["summary"]["rules_by_proto"] = dict(rules_by_proto)
    
    # 分析每个Rmax组内的规则关系
    for rmax_id, group_rules in rmax_groups.items():
        rmax_rule = rmax_rules_dict[rmax_id]
        results["rmax_details"][rmax_id] = {
            "proto": rmax_rule.proto,
            "src_range": f"{int_to_ip(rmax_rule.src_lo)}-{int_to_ip(rmax_rule.src_hi)}",
            "dst_range": f"{int_to_ip(rmax_rule.dst_lo)}-{int_to_ip(rmax_rule.dst_hi)}",
            "member_count": len(group_rules),
            "members": [r.index for r in group_rules]
        }
        
        # 分析组内规则对的关系
        n = len(group_rules)
        print(f"分析Rmax {rmax_id} (协议 {rmax_rule.proto}): {n} 条规则, {n*(n-1)//2} 对组合...")
        
        for i in range(n):
            for j in range(i + 1, n):
                r1, r2 = group_rules[i], group_rules[j]
                rel_type, intersect_info = rule_relation(r1, r2)
                
                results["summary"]["total_pairs_checked"] += 1
                
                if rel_type == "DISJOINT":
                    results["summary"]["disjoint_pairs"] += 1
                elif rel_type == "EQUAL":
                    results["summary"]["equal_pairs"] += 1
                elif rel_type in ("R1_SUBSET_R2", "R2_SUBSET_R1"):
                    results["summary"]["subset_pairs"] += 1
                    results["subset_relations"].append({
                        "rmax_id": rmax_id,
                        "rule_a": r1.index,
                        "rule_b": r2.index,
                        "type": rel_type,
                        "region": intersect_info
                    })
                elif rel_type == "PARTIAL_INTERSECT":
                    results["summary"]["partial_intersect_pairs"] += 1
                    results["partial_intersections"].append({
                        "rmax_id": rmax_id,
                        "rule_a": r1.index,
                        "rule_b": r2.index,
                        "rule_a_info": {
                            "src": f"{int_to_ip(r1.src_lo)} - {int_to_ip(r1.src_hi)}",
                            "dst": f"{int_to_ip(r1.dst_lo)} - {int_to_ip(r1.dst_hi)}"
                        },
                        "rule_b_info": {
                            "src": f"{int_to_ip(r2.src_lo)} - {int_to_ip(r2.src_hi)}",
                            "dst": f"{int_to_ip(r2.dst_lo)} - {int_to_ip(r2.dst_hi)}"
                        },
                        "intersection_region": intersect_info
                    })
    
    # 分析跨Rmax的相交关系
    for proto, rmax_list in rmax_by_proto.items():
        print(f"分析协议 {proto} 内的跨Rmax相交: {len(rmax_list)} 个Rmax...")
        n = len(rmax_list)
        for i in range(n):
            for j in range(i + 1, n):
                rmax_id1, rmax_id2 = rmax_list[i], rmax_list[j]
                rmax1, rmax2 = rmax_rules_dict[rmax_id1], rmax_rules_dict[rmax_id2]
                
                # 检查两个Rmax是否有交集
                src_overlap = not (rmax1.src_hi < rmax2.src_lo or rmax2.src_hi < rmax1.src_lo)
                dst_overlap = not (rmax1.dst_hi < rmax2.dst_lo or rmax2.dst_hi < rmax1.dst_lo)
                
                if src_overlap and dst_overlap:
                    # 计算交集区域
                    intersect_src_lo = max(rmax1.src_lo, rmax2.src_lo)
                    intersect_src_hi = min(rmax1.src_hi, rmax2.src_hi)
                    intersect_dst_lo = max(rmax1.dst_lo, rmax2.dst_lo)
                    intersect_dst_hi = min(rmax1.dst_hi, rmax2.dst_hi)
                    
                    intersect_info = {
                        "src_lo": int_to_ip(intersect_src_lo),
                        "src_hi": int_to_ip(intersect_src_hi),
                        "dst_lo": int_to_ip(intersect_dst_lo),
                        "dst_hi": int_to_ip(intersect_dst_hi),
                        "proto": proto
                    }
                    
                    results["summary"]["cross_rmax_intersections"] += 1
                    results["cross_rmax_intersections"].append({
                        "rmax_a": rmax_id1,
                        "rmax_b": rmax_id2,
                        "rmax_a_info": {
                            "src": f"{int_to_ip(rmax1.src_lo)} - {int_to_ip(rmax1.src_hi)}",
                            "dst": f"{int_to_ip(rmax1.dst_lo)} - {int_to_ip(rmax1.dst_hi)}"
                        },
                        "rmax_b_info": {
                            "src": f"{int_to_ip(rmax2.src_lo)} - {int_to_ip(rmax2.src_hi)}",
                            "dst": f"{int_to_ip(rmax2.dst_lo)} - {int_to_ip(rmax2.dst_hi)}"
                        },
                        "intersection_region": intersect_info
                    })
    
    return results

def print_report(results: Dict):
    """打印分析报告"""
    summary = results["summary"]
    
    print("\n" + "=" * 80)
    print("                    Merged IP Table 相交关系分析报告")
    print("=" * 80)
    
    print(f"\n【基本统计】")
    print(f"  总规则数: {summary['total_rules']}")
    print(f"  总Rmax数: {summary['total_rmax']}")
    print(f"  按协议规则分布: {summary['rules_by_proto']}")
    print(f"  按协议Rmax分布: {summary['rmax_by_proto']}")
    print(f"  检查的规则对数: {summary['total_pairs_checked']}")
    
    print(f"\n【关系分类】")
    print(f"  完全不相交 (DISJOINT):     {summary['disjoint_pairs']}")
    print(f"  完全相等 (EQUAL):          {summary['equal_pairs']}")
    print(f"  包含关系 (SUBSET):         {summary['subset_pairs']}")
    print(f"  ★ 部分相交 (INTERSECT):    {summary['partial_intersect_pairs']}  ← 产生 intersection cell 的来源")
    print(f"  ★ 跨Rmax相交:              {summary['cross_rmax_intersections']}  ← 跨Rmax的相交关系")
    
    if results["partial_intersections"]:
        print(f"\n【部分相交详情】(前 20 条)")
        for i, item in enumerate(results["partial_intersections"][:20]):
            print(f"\n  #{i+1}: Rmax[{item['rmax_id']}] 内 Rule[{item['rule_a']}] ∩ Rule[{item['rule_b']}]")
            print(f"       Rule[{item['rule_a']}]: src={item['rule_a_info']['src']}, dst={item['rule_a_info']['dst']}")
            print(f"       Rule[{item['rule_b']}]: src={item['rule_b_info']['src']}, dst={item['rule_b_info']['dst']}")
            region = item['intersection_region']
            print(f"       相交区域: src={region['src_lo']}-{region['src_hi']}, dst={region['dst_lo']}-{region['dst_hi']}, proto={region['proto']}")
    
    if results["cross_rmax_intersections"]:
        print(f"\n【跨Rmax相交详情】(前 10 条)")
        for i, item in enumerate(results["cross_rmax_intersections"][:10]):
            print(f"\n  #{i+1}: Rmax[{item['rmax_a']}] ∩ Rmax[{item['rmax_b']}]")
            print(f"       Rmax[{item['rmax_a']}]: src={item['rmax_a_info']['src']}, dst={item['rmax_a_info']['dst']}")
            print(f"       Rmax[{item['rmax_b']}]: src={item['rmax_b_info']['src']}, dst={item['rmax_b_info']['dst']}")
            region = item['intersection_region']
            print(f"       相交区域: src={region['src_lo']}-{region['src_hi']}, dst={region['dst_lo']}-{region['dst_hi']}, proto={region['proto']}")
    
    # 显示部分Rmax详情
    print(f"\n【Rmax组详情】(前 10 个)")
    count = 0
    for rmax_id, details in results["rmax_details"].items():
        if count >= 10:
            break
        print(f"\n  Rmax[{rmax_id}]: 协议={details['proto']}, 成员数={details['member_count']}")
        print(f"    SRC范围: {details['src_range']}")
        print(f"    DST范围: {details['dst_range']}")
        print(f"    成员: {details['members'][:10]}{'...' if len(details['members']) > 10 else ''}")
        count += 1
    
    print("\n" + "=" * 80)

def visualize_intersections(results: Dict, num_samples: int = 6):
    """可视化随机抽取的相交规则对"""
    try:
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
    except ImportError:
        print("错误: 需要安装 matplotlib。运行: pip install matplotlib")
        return
    
    partial_intersections = results['partial_intersections']
    total = len(partial_intersections)
    
    if total == 0:
        print("没有部分相交的规则对，无法可视化")
        return
    
    num_samples = min(num_samples, total)
    sampled_pairs = random.sample(partial_intersections, num_samples)
    
    print(f"\n随机抽取 {num_samples} 对进行可视化:")
    for i, pair in enumerate(sampled_pairs):
        print(f"  #{i+1}: Rule[{pair['rule_a']}] ∩ Rule[{pair['rule_b']}]")
    
    # 计算子图布局
    cols = min(3, num_samples)
    rows = (num_samples + cols - 1) // cols
    
    fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 5 * rows))
    if num_samples == 1:
        axes = [axes]
    else:
        axes = axes.flatten() if hasattr(axes, 'flatten') else [axes]
    
    for i, pair in enumerate(sampled_pairs):
        ax = axes[i]
        _draw_intersection_pair(pair, i, ax)
    
    # 隐藏多余的子图
    for i in range(num_samples, len(axes)):
        axes[i].axis('off')
    
    plt.suptitle('Merged IP Rules Intersection (Blue=Rule A, Green=Rule B, Red=Intersection)', fontsize=12)
    plt.tight_layout()
    
    output_file = 'src/output/intersection_visualization.png'
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\n可视化结果已保存到: {output_file}")
    
    plt.show()
    
    # 打印详细信息
    print("\n" + "=" * 80)
    print("抽样详细信息:")
    print("=" * 80)
    for i, pair in enumerate(sampled_pairs):
        print(f"\n【Pair #{i+1}】Rule[{pair['rule_a']}] ∩ Rule[{pair['rule_b']}]")
        print(f"  Rule[{pair['rule_a']}]:")
        print(f"    SRC: {pair['rule_a_info']['src']}")
        print(f"    DST: {pair['rule_a_info']['dst']}")
        print(f"  Rule[{pair['rule_b']}]:")
        print(f"    SRC: {pair['rule_b_info']['src']}")
        print(f"    DST: {pair['rule_b_info']['dst']}")
        region = pair['intersection_region']
        print(f"  相交区域:")
        print(f"    SRC: {region['src_lo']} - {region['src_hi']}")
        print(f"    DST: {region['dst_lo']} - {region['dst_hi']}")
        print(f"    Proto: {region['proto']}")

def visualize_all_rules(rules: List[IPRule], results: Dict, highlight_rules: List[int] = None):
    """可视化所有规则和相交区域（按协议分组）
    
    Args:
        rules: 规则列表
        results: 分析结果
        highlight_rules: 需要高亮标注的规则索引列表（如 [0,1,2,...,10]）
    """
    try:
        import matplotlib.pyplot as plt
        import matplotlib.patches as patches
    except ImportError:
        print("错误: 需要安装 matplotlib。运行: pip install matplotlib")
        return
    
    # 按协议分组规则
    rules_by_proto = defaultdict(list)
    for r in rules:
        rules_by_proto[r.proto].append(r)
    
    # 为每个协议生成图表
    for proto, proto_rules in rules_by_proto.items():
        if not proto_rules:
            continue
            
        fig, ax = plt.subplots(1, 1, figsize=(12, 10))
        
        # 绘制所有规则
        for rule in proto_rules:
            # 绘制源IP矩形
            src_width = (rule.src_hi - rule.src_lo) / (2**32)
            src_height = 0.4
            src_rect = patches.Rectangle(
                (rule.src_lo / (2**32), 0.3), 
                src_width, src_height,
                linewidth=1, edgecolor='blue', facecolor='lightblue', alpha=0.5
            )
            ax.add_patch(src_rect)
            
            # 绘制目标IP矩形
            dst_width = (rule.dst_hi - rule.dst_lo) / (2**32)
            dst_height = 0.4
            dst_rect = patches.Rectangle(
                (rule.dst_lo / (2**32), 1.3), 
                dst_width, dst_height,
                linewidth=1, edgecolor='green', facecolor='lightgreen', alpha=0.5
            )
            ax.add_patch(dst_rect)
            
            # 如果需要高亮，则添加标签
            if highlight_rules and rule.index in highlight_rules:
                ax.text(
                    rule.src_lo / (2**32), 0.5, 
                    f'R{rule.index}', 
                    ha='left', va='center',
                    fontsize=8, color='darkblue'
                )
        
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 2)
        ax.set_xlabel('IP Address Space (Normalized)')
        ax.set_title(f'Protocol {proto} Rules Visualization')
        ax.grid(True, alpha=0.3)
        
        # 保存图像
        output_file = f'src/output/all_rules_proto_{proto}.png'
        plt.savefig(output_file, dpi=150, bbox_inches='tight')
        print(f"协议 {proto} 的所有规则可视化已保存到: {output_file}")
        plt.close()

def _draw_intersection_pair(pair: Dict, index: int, ax):
    """绘制一对相交规则"""
    try:
        import matplotlib.patches as patches
    except ImportError:
        return
    
    # 解析规则A的信息
    rule_a_src_parts = pair['rule_a_info']['src'].split(' - ')
    rule_a_dst_parts = pair['rule_a_info']['dst'].split(' - ')
    a_src_lo = ip_to_int(rule_a_src_parts[0])
    a_src_hi = ip_to_int(rule_a_src_parts[1])
    a_dst_lo = ip_to_int(rule_a_dst_parts[0])
    a_dst_hi = ip_to_int(rule_a_dst_parts[1])
    
    # 解析规则B的信息
    rule_b_src_parts = pair['rule_b_info']['src'].split(' - ')
    rule_b_dst_parts = pair['rule_b_info']['dst'].split(' - ')
    b_src_lo = ip_to_int(rule_b_src_parts[0])
    b_src_hi = ip_to_int(rule_b_src_parts[1])
    b_dst_lo = ip_to_int(rule_b_dst_parts[0])
    b_dst_hi = ip_to_int(rule_b_dst_parts[1])
    
    # 解析相交区域信息
    region = pair['intersection_region']
    intersect_src_lo = ip_to_int(region['src_lo'])
    intersect_src_hi = ip_to_int(region['src_hi'])
    intersect_dst_lo = ip_to_int(region['dst_lo'])
    intersect_dst_hi = ip_to_int(region['dst_hi'])
    
    # 绘制SRC维度
    # 规则A (蓝色)
    a_src_width = (a_src_hi - a_src_lo) / (2**32)
    a_src_rect = patches.Rectangle(
        (a_src_lo / (2**32), 0.1), a_src_width, 0.8,
        linewidth=1, edgecolor='blue', facecolor='lightblue', alpha=0.7, label=f"Rule {pair['rule_a']}"
    )
    ax.add_patch(a_src_rect)
    
    # 规则B (绿色)
    b_src_width = (b_src_hi - b_src_lo) / (2**32)
    b_src_rect = patches.Rectangle(
        (b_src_lo / (2**32), 0.1), b_src_width, 0.8,
        linewidth=1, edgecolor='green', facecolor='lightgreen', alpha=0.7, label=f"Rule {pair['rule_b']}"
    )
    ax.add_patch(b_src_rect)
    
    # 相交区域 (红色)
    intersect_src_width = (intersect_src_hi - intersect_src_lo) / (2**32)
    intersect_src_rect = patches.Rectangle(
        (intersect_src_lo / (2**32), 0.1), intersect_src_width, 0.8,
        linewidth=2, edgecolor='red', facecolor='pink', alpha=0.7, label='Intersection'
    )
    ax.add_patch(intersect_src_rect)
    
    # 绘制DST维度
    # 规则A (蓝色)
    a_dst_width = (a_dst_hi - a_dst_lo) / (2**32)
    a_dst_rect = patches.Rectangle(
        (a_dst_lo / (2**32), 1.1), a_dst_width, 0.8,
        linewidth=1, edgecolor='blue', facecolor='lightblue', alpha=0.7
    )
    ax.add_patch(a_dst_rect)
    
    # 规则B (绿色)
    b_dst_width = (b_dst_hi - b_dst_lo) / (2**32)
    b_dst_rect = patches.Rectangle(
        (b_dst_lo / (2**32), 1.1), b_dst_width, 0.8,
        linewidth=1, edgecolor='green', facecolor='lightgreen', alpha=0.7
    )
    ax.add_patch(b_dst_rect)
    
    # 相交区域 (红色)
    intersect_dst_width = (intersect_dst_hi - intersect_dst_lo) / (2**32)
    intersect_dst_rect = patches.Rectangle(
        (intersect_dst_lo / (2**32), 1.1), intersect_dst_width, 0.8,
        linewidth=2, edgecolor='red', facecolor='pink', alpha=0.7
    )
    ax.add_patch(intersect_dst_rect)
    
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 2)
    ax.set_xlabel('IP Address Space (Normalized)')
    ax.set_ylabel('Dimension (SRC=0-1, DST=1-2)')
    ax.set_title(f'Pair #{index+1}: Rule {pair["rule_a"]} ∩ Rule {pair["rule_b"]}')
    ax.legend()
    ax.grid(True, alpha=0.3)

def save_detailed_results(results: Dict, output_file: str = "src/output/intersection_analysis.json"):
    """保存详细分析结果到JSON文件"""
    # 转换所有整数键为字符串，以便JSON序列化
    def convert_keys(obj):
        if isinstance(obj, dict):
            return {str(k): convert_keys(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_keys(item) for item in obj]
        else:
            return obj
    
    converted_results = convert_keys(results)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_results, f, ensure_ascii=False, indent=2)
    
    print(f"\n详细分析结果已保存到: {output_file}")

def main():
    # 加载规则
    merged_ip_table_file = 'src/output/merged_ip_table.txt'
    print("加载 merged_ip_table...")
    rules = load_merged_ip_table(merged_ip_table_file)
    print(f"加载了 {len(rules)} 条规则")
    
    # 分析相交关系
    print("开始分析规则间的相交关系...")
    results = analyze_intersections_by_rmax(rules)
    
    # 打印报告
    print_report(results)
    
    # 保存详细结果
    save_detailed_results(results)
    
    # 可视化选项
    if "--visualize" in sys.argv:
        num_samples = 6
        if len(sys.argv) > 2:
            try:
                num_samples = int(sys.argv[2])
            except ValueError:
                pass
        visualize_intersections(results, num_samples)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())