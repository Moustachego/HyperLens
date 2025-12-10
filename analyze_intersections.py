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

def analyze_all_relations(rules: List[IPRule]) -> Dict:
    """分析所有规则对之间的关系"""
    
    # 按协议分组
    rules_by_proto = defaultdict(list)
    for r in rules:
        rules_by_proto[r.proto].append(r)
    
    results = {
        "summary": {
            "total_rules": len(rules),
            "rules_by_proto": {proto: len(rs) for proto, rs in rules_by_proto.items()},
            "total_pairs_checked": 0,
            "disjoint_pairs": 0,
            "equal_pairs": 0,
            "subset_pairs": 0,  # 包含关系
            "partial_intersect_pairs": 0  # ★ 这是产生 intersection cell 的来源
        },
        "partial_intersections": [],  # 详细的部分相交信息
        "subset_relations": []  # 包含关系
    }
    
    # 只在同协议内分析
    for proto, proto_rules in rules_by_proto.items():
        n = len(proto_rules)
        print(f"分析协议 {proto}: {n} 条规则, {n*(n-1)//2} 对组合...")
        
        for i in range(n):
            for j in range(i + 1, n):
                r1, r2 = proto_rules[i], proto_rules[j]
                rel_type, intersect_info = rule_relation(r1, r2)
                
                results["summary"]["total_pairs_checked"] += 1
                
                if rel_type == "DISJOINT":
                    results["summary"]["disjoint_pairs"] += 1
                elif rel_type == "EQUAL":
                    results["summary"]["equal_pairs"] += 1
                elif rel_type in ("R1_SUBSET_R2", "R2_SUBSET_R1"):
                    results["summary"]["subset_pairs"] += 1
                    results["subset_relations"].append({
                        "rule_a": r1.index,
                        "rule_b": r2.index,
                        "type": rel_type,
                        "region": intersect_info
                    })
                elif rel_type == "PARTIAL_INTERSECT":
                    results["summary"]["partial_intersect_pairs"] += 1
                    results["partial_intersections"].append({
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
    
    return results

def print_report(results: Dict):
    """打印分析报告"""
    summary = results["summary"]
    
    print("\n" + "=" * 80)
    print("                    Merged IP Table 相交关系分析报告")
    print("=" * 80)
    
    print(f"\n【基本统计】")
    print(f"  总规则数: {summary['total_rules']}")
    print(f"  按协议分布: {summary['rules_by_proto']}")
    print(f"  检查的规则对数: {summary['total_pairs_checked']}")
    
    print(f"\n【关系分类】")
    print(f"  完全不相交 (DISJOINT):     {summary['disjoint_pairs']}")
    print(f"  完全相等 (EQUAL):          {summary['equal_pairs']}")
    print(f"  包含关系 (SUBSET):         {summary['subset_pairs']}")
    print(f"  ★ 部分相交 (INTERSECT):    {summary['partial_intersect_pairs']}  ← 产生 intersection cell 的来源")
    
    if results["partial_intersections"]:
        print(f"\n【部分相交详情】(前 20 条)")
        for i, item in enumerate(results["partial_intersections"][:20]):
            print(f"\n  #{i+1}: Rule[{item['rule_a']}] ∩ Rule[{item['rule_b']}]")
            print(f"       Rule[{item['rule_a']}]: src={item['rule_a_info']['src']}, dst={item['rule_a_info']['dst']}")
            print(f"       Rule[{item['rule_b']}]: src={item['rule_b_info']['src']}, dst={item['rule_b_info']['dst']}")
            region = item['intersection_region']
            print(f"       相交区域: src={region['src_lo']}-{region['src_hi']}, dst={region['dst_lo']}-{region['dst_hi']}, proto={region['proto']}")
    
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
        from matplotlib.collections import PatchCollection
        import numpy as np
    except ImportError:
        print("错误: 需要安装 matplotlib。运行: pip install matplotlib")
        return
    
    if highlight_rules is None:
        highlight_rules = []
    
    # 按协议分组
    rules_by_proto = defaultdict(list)
    for r in rules:
        rules_by_proto[r.proto].append(r)
    
    # 获取相交规则的索引
    intersecting_rules = set()
    for item in results['partial_intersections']:
        intersecting_rules.add(item['rule_a'])
        intersecting_rules.add(item['rule_b'])
    
    # 相交区域按协议分组
    intersections_by_proto = defaultdict(list)
    for item in results['partial_intersections']:
        proto = item['intersection_region']['proto']
        intersections_by_proto[proto].append(item)
    
    proto_names = {0: 'HOPOPT/Any', 1: 'ICMP', 6: 'TCP', 17: 'UDP'}
    
    # 创建每个协议一张图
    protos = sorted(rules_by_proto.keys())
    n_protos = len(protos)
    
    fig, axes = plt.subplots(1, n_protos, figsize=(7 * n_protos, 7))
    if n_protos == 1:
        axes = [axes]
    
    for ax_idx, proto in enumerate(protos):
        ax = axes[ax_idx]
        proto_rules = rules_by_proto[proto]
        proto_intersections = intersections_by_proto.get(proto, [])
        
        # 计算归一化范围
        all_src = []
        all_dst = []
        for r in proto_rules:
            all_src.extend([r.src_lo, r.src_hi])
            all_dst.extend([r.dst_lo, r.dst_hi])
        
        if not all_src:
            continue
            
        src_min, src_max = min(all_src), max(all_src)
        dst_min, dst_max = min(all_dst), max(all_dst)
        
        # 避免除以零
        src_range = max(src_max - src_min, 1)
        dst_range = max(dst_max - dst_min, 1)
        
        def norm_src(x):
            return (x - src_min) / src_range * 100
        def norm_dst(x):
            return (x - dst_min) / dst_range * 100
        
        # 先绘制普通规则（灰色/蓝色）
        for r in proto_rules:
            is_intersecting = r.index in intersecting_rules
            is_highlighted = r.index in highlight_rules
            
            if is_highlighted:
                continue  # 高亮规则稍后绘制
            elif is_intersecting:
                color = 'blue'
                alpha = 0.3
                linewidth = 1
            else:
                color = 'gray'
                alpha = 0.1
                linewidth = 0.5
            
            w = norm_src(r.src_hi) - norm_src(r.src_lo)
            h = norm_dst(r.dst_hi) - norm_dst(r.dst_lo)
            rect = patches.Rectangle(
                (norm_src(r.src_lo), norm_dst(r.dst_lo)),
                max(w, 0.5), max(h, 0.5),
                linewidth=linewidth, edgecolor=color, facecolor=color, alpha=alpha
            )
            ax.add_patch(rect)
        
        # 绘制相交区域（红色高亮）
        for item in proto_intersections:
            region = item['intersection_region']
            i_src_lo = ip_to_int(region['src_lo'])
            i_src_hi = ip_to_int(region['src_hi'])
            i_dst_lo = ip_to_int(region['dst_lo'])
            i_dst_hi = ip_to_int(region['dst_hi'])
            
            w = norm_src(i_src_hi) - norm_src(i_src_lo)
            h = norm_dst(i_dst_hi) - norm_dst(i_dst_lo)
            rect = patches.Rectangle(
                (norm_src(i_src_lo), norm_dst(i_dst_lo)),
                max(w, 0.5), max(h, 0.5),
                linewidth=2, edgecolor='red', facecolor='red', alpha=0.5
            )
            ax.add_patch(rect)
        
        # 最后绘制高亮规则（确保在最上层）
        # 先收集所有高亮规则的位置
        highlight_data = []
        for r in proto_rules:
            if r.index not in highlight_rules:
                continue
            
            w = norm_src(r.src_hi) - norm_src(r.src_lo)
            h = norm_dst(r.dst_hi) - norm_dst(r.dst_lo)
            center_x = norm_src(r.src_lo) + w / 2
            center_y = norm_dst(r.dst_lo) + h / 2
            highlight_data.append((r.index, center_x, center_y, w, h))
        
        # 用于跟踪已使用的标签位置，避免重叠
        used_label_positions = []
        
        for idx, center_x, center_y, w, h in highlight_data:
            # 用星号标记真实位置（不放大）
            ax.plot(center_x, center_y, 'g*', markersize=15, zorder=10, 
                    markeredgecolor='darkgreen', markeredgewidth=1)
            
            # 如果规则有实际大小，也画出真实的矩形
            if w > 0.1 or h > 0.1:
                rect = patches.Rectangle(
                    (norm_src(r.src_lo), norm_dst(r.dst_lo)),
                    max(w, 0.5), max(h, 0.5),
                    linewidth=2, edgecolor='lime', facecolor='lime', alpha=0.5,
                    zorder=9
                )
                ax.add_patch(rect)
            
            # 计算基础标签偏移方向
            base_offset_x = 8 if center_x < 50 else -8
            base_offset_y = 8 if center_y < 50 else -8
            
            # 尝试不同的偏移量，避免标签重叠
            label_x = center_x + base_offset_x
            label_y = center_y + base_offset_y
            
            # 检查是否与已有标签重叠，如果重叠则调整位置
            offset_multiplier = 1
            while any(abs(label_x - px) < 6 and abs(label_y - py) < 6 for px, py in used_label_positions):
                offset_multiplier += 1
                # 尝试不同方向
                if offset_multiplier % 4 == 1:
                    label_x = center_x + base_offset_x * offset_multiplier
                    label_y = center_y + base_offset_y
                elif offset_multiplier % 4 == 2:
                    label_x = center_x + base_offset_x
                    label_y = center_y + base_offset_y * offset_multiplier
                elif offset_multiplier % 4 == 3:
                    label_x = center_x - base_offset_x
                    label_y = center_y + base_offset_y
                else:
                    label_x = center_x + base_offset_x
                    label_y = center_y - base_offset_y
                
                if offset_multiplier > 8:
                    break  # 避免无限循环
            
            used_label_positions.append((label_x, label_y))
            
            ax.annotate(
                f'R{idx}', 
                xy=(center_x, center_y),
                xytext=(label_x, label_y),
                fontsize=10, fontweight='bold', color='darkred',
                ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', edgecolor='orange', linewidth=2),
                arrowprops=dict(arrowstyle='->', color='orange', lw=2),
                zorder=20
            )
        
        ax.set_xlim(-2, 102)
        ax.set_ylim(-2, 102)
        ax.set_xlabel('SRC IP (normalized)', fontsize=10)
        ax.set_ylabel('DST IP (normalized)', fontsize=10)
        
        proto_name = proto_names.get(proto, f'Proto {proto}')
        n_rules = len(proto_rules)
        n_intersect = len(proto_intersections)
        n_involved = len([r for r in proto_rules if r.index in intersecting_rules])
        
        ax.set_title(f'{proto_name}\n{n_rules} rules, {n_involved} involved in {n_intersect} intersections', fontsize=11)
        ax.set_aspect('equal')
        ax.grid(True, alpha=0.3)
    
    plt.suptitle('All Merged IP Rules by Protocol\n(Gray=isolated, Blue=has intersection, Red=intersection region)', fontsize=14)
    plt.tight_layout()
    
    output_file = 'src/output/all_rules_visualization.png'
    plt.savefig(output_file, dpi=200, bbox_inches='tight')
    print(f"\n全局可视化结果已保存到: {output_file}")
    
    plt.show()

def _draw_intersection_pair(pair_info: dict, pair_idx: int, ax):
    """在一个子图上绘制一对相交规则"""
    import matplotlib.patches as patches
    
    rule_a_info = pair_info['rule_a_info']
    rule_b_info = pair_info['rule_b_info']
    intersect = pair_info['intersection_region']
    
    # 解析范围
    src_a = rule_a_info['src'].split(' - ')
    dst_a = rule_a_info['dst'].split(' - ')
    a_src_lo, a_src_hi = ip_to_int(src_a[0]), ip_to_int(src_a[1])
    a_dst_lo, a_dst_hi = ip_to_int(dst_a[0]), ip_to_int(dst_a[1])
    
    src_b = rule_b_info['src'].split(' - ')
    dst_b = rule_b_info['dst'].split(' - ')
    b_src_lo, b_src_hi = ip_to_int(src_b[0]), ip_to_int(src_b[1])
    b_dst_lo, b_dst_hi = ip_to_int(dst_b[0]), ip_to_int(dst_b[1])
    
    i_src_lo, i_src_hi = ip_to_int(intersect['src_lo']), ip_to_int(intersect['src_hi'])
    i_dst_lo, i_dst_hi = ip_to_int(intersect['dst_lo']), ip_to_int(intersect['dst_hi'])
    
    # 计算显示范围
    all_src = [a_src_lo, a_src_hi, b_src_lo, b_src_hi]
    all_dst = [a_dst_lo, a_dst_hi, b_dst_lo, b_dst_hi]
    src_min, src_max = min(all_src), max(all_src)
    dst_min, dst_max = min(all_dst), max(all_dst)
    
    # 归一化函数
    def norm_src(x):
        return 50 if src_max == src_min else (x - src_min) / (src_max - src_min) * 100
    def norm_dst(x):
        return 50 if dst_max == dst_min else (x - dst_min) / (dst_max - dst_min) * 100
    
    # 绘制 Rule A (蓝色)
    rect_a = patches.Rectangle(
        (norm_src(a_src_lo), norm_dst(a_dst_lo)),
        norm_src(a_src_hi) - norm_src(a_src_lo) or 1,
        norm_dst(a_dst_hi) - norm_dst(a_dst_lo) or 1,
        linewidth=2, edgecolor='blue', facecolor='blue', alpha=0.3,
        label=f"Rule[{pair_info['rule_a']}]"
    )
    ax.add_patch(rect_a)
    
    # 绘制 Rule B (绿色)
    rect_b = patches.Rectangle(
        (norm_src(b_src_lo), norm_dst(b_dst_lo)),
        norm_src(b_src_hi) - norm_src(b_src_lo) or 1,
        norm_dst(b_dst_hi) - norm_dst(b_dst_lo) or 1,
        linewidth=2, edgecolor='green', facecolor='green', alpha=0.3,
        label=f"Rule[{pair_info['rule_b']}]"
    )
    ax.add_patch(rect_b)
    
    # 绘制相交区域 (红色)
    rect_i = patches.Rectangle(
        (norm_src(i_src_lo), norm_dst(i_dst_lo)),
        norm_src(i_src_hi) - norm_src(i_src_lo) or 1,
        norm_dst(i_dst_hi) - norm_dst(i_dst_lo) or 1,
        linewidth=3, edgecolor='red', facecolor='red', alpha=0.5,
        label='Intersection'
    )
    ax.add_patch(rect_i)
    
    ax.set_xlim(-5, 105)
    ax.set_ylim(-5, 105)
    ax.set_xticks([0, 50, 100])
    ax.set_xticklabels([int_to_ip(src_min), int_to_ip((src_min + src_max) // 2), int_to_ip(src_max)], fontsize=7, rotation=15)
    ax.set_yticks([0, 50, 100])
    ax.set_yticklabels([int_to_ip(dst_min), int_to_ip((dst_min + dst_max) // 2), int_to_ip(dst_max)], fontsize=7)
    ax.set_xlabel('SRC IP', fontsize=9)
    ax.set_ylabel('DST IP', fontsize=9)
    ax.set_title(f"#{pair_idx+1}: Rule[{pair_info['rule_a']}] ∩ Rule[{pair_info['rule_b']}]", fontsize=10)
    ax.legend(loc='upper right', fontsize=7)
    ax.set_aspect('equal')
    ax.grid(True, alpha=0.3)

def main():
    input_file = "src/output/merged_ip_table.txt"
    output_json = "src/output/intersection_analysis.json"
    output_csv = "src/output/partial_intersections.csv"
    
    # 解析命令行参数
    visualize = False
    visualize_all = False
    num_visualize = 6
    highlight_rules = []
    
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--visualize':
            visualize = True
            # 检查下一个参数是否是数字
            if i + 1 < len(args) and args[i + 1].isdigit():
                i += 1
                num_visualize = int(args[i])
        elif arg == '--all':
            visualize_all = True
        elif arg == '--highlight':
            # 解析高亮规则，格式: --highlight 0-10 或 --highlight 0,1,2,3
            if i + 1 < len(args):
                i += 1
                hl_arg = args[i]
                if '-' in hl_arg and ',' not in hl_arg:
                    # 范围格式: 0-10
                    parts = hl_arg.split('-')
                    start, end = int(parts[0]), int(parts[1])
                    highlight_rules = list(range(start, end + 1))
                else:
                    # 逗号分隔格式: 0,1,2,3
                    highlight_rules = [int(x) for x in hl_arg.split(',')]
        elif not arg.startswith('--'):
            input_file = arg
        i += 1
    
    print(f"加载 {input_file}...")
    rules = load_merged_ip_table(input_file)
    print(f"加载了 {len(rules)} 条 merged IP 规则")
    
    print("\n开始分析规则间的相交关系...")
    results = analyze_all_relations(rules)
    
    # 打印报告
    print_report(results)
    
    # 保存 JSON
    with open(output_json, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n详细结果已保存到: {output_json}")
    
    # 保存 CSV (只包含部分相交)
    with open(output_csv, 'w') as f:
        f.write("RuleA,RuleB,IntersectSrcLo,IntersectSrcHi,IntersectDstLo,IntersectDstHi,Proto\n")
        for item in results["partial_intersections"]:
            region = item["intersection_region"]
            f.write(f"{item['rule_a']},{item['rule_b']},{region['src_lo']},{region['src_hi']},{region['dst_lo']},{region['dst_hi']},{region['proto']}\n")
    print(f"部分相交列表已保存到: {output_csv}")
    
    # 可视化
    if visualize_all:
        if highlight_rules:
            print(f"\n高亮显示规则: R{min(highlight_rules)} - R{max(highlight_rules)}")
        visualize_all_rules(rules, results, highlight_rules)
    elif visualize:
        visualize_intersections(results, num_visualize)

if __name__ == "__main__":
    main()
