#!/usr/bin/env python3
"""
分析 Intersection Cells 膨胀的原因

核心问题：为什么 146 个成对相交关系 → 675 个 intersection cells？

原因：C++ 算法使用"网格分解"（Grid Decomposition）
当多条规则相互重叠时，它们的边界会将2D空间切割成多个独立的"单元格"(cells)

例如：3条规则两两相交
- Python分析：3对相交关系
- C++算法：可能产生9个或更多的单元格（包括交集区域）

本脚本通过分析 merged_ip_table.txt 来模拟这个过程
"""

import sys
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Tuple, Set, Dict
import os

@dataclass
class IPRule:
    idx: int
    src_lo: int
    src_hi: int
    dst_lo: int
    dst_hi: int
    proto: int
    priority: int

def ip_to_int(ip_str: str) -> int:
    """Convert IP string to integer"""
    parts = ip_str.split('.')
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

def int_to_ip(ip_int: int) -> str:
    """Convert integer to IP string"""
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"

def load_merged_ip_table(filepath: str) -> List[IPRule]:
    """Load merged IP table from file (tab-separated with header)"""
    rules = []
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    # Skip header line
    for line_num, line in enumerate(lines[1:], start=1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')  # Tab-separated
        if len(parts) < 7:
            continue
        try:
            rule = IPRule(
                idx=int(parts[0]),  # Index column
                src_lo=ip_to_int(parts[1]),
                src_hi=ip_to_int(parts[2]),
                dst_lo=ip_to_int(parts[3]),
                dst_hi=ip_to_int(parts[4]),
                proto=int(parts[5]),
                priority=int(parts[6])
            )
            rules.append(rule)
        except (ValueError, IndexError) as e:
            continue
    return rules

def rules_intersect(a: IPRule, b: IPRule) -> bool:
    """Check if two rules have a non-empty intersection"""
    if a.proto != b.proto:
        return False
    src_lo = max(a.src_lo, b.src_lo)
    src_hi = min(a.src_hi, b.src_hi)
    dst_lo = max(a.dst_lo, b.dst_lo)
    dst_hi = min(a.dst_hi, b.dst_hi)
    return src_lo <= src_hi and dst_lo <= dst_hi

def rule_contains(outer: IPRule, inner: IPRule) -> bool:
    """Check if outer completely contains inner (same proto)"""
    if outer.proto != inner.proto:
        return False
    return (outer.src_lo <= inner.src_lo and inner.src_hi <= outer.src_hi and
            outer.dst_lo <= inner.dst_lo and inner.dst_hi <= outer.dst_hi)

def is_proper_intersection(a: IPRule, b: IPRule) -> bool:
    """Check if a and b have PROPER intersection (partial overlap, not subset)"""
    if a.proto != b.proto:
        return False
    # First check they intersect
    src_lo = max(a.src_lo, b.src_lo)
    src_hi = min(a.src_hi, b.src_hi)
    dst_lo = max(a.dst_lo, b.dst_lo)
    dst_hi = min(a.dst_hi, b.dst_hi)
    if src_lo > src_hi or dst_lo > dst_hi:
        return False
    
    # Check it's not a subset relationship
    a_contains_b = rule_contains(a, b)
    b_contains_a = rule_contains(b, a)
    
    return not a_contains_b and not b_contains_a

def build_elementary_intervals(rules: List[IPRule], proto: int) -> Tuple[List[int], List[int]]:
    """Build elementary intervals for a protocol (grid decomposition)"""
    proto_rules = [r for r in rules if r.proto == proto]
    
    # Collect all endpoints
    src_endpoints = set()
    dst_endpoints = set()
    
    for r in proto_rules:
        src_endpoints.add(r.src_lo)
        src_endpoints.add(r.src_hi)
        dst_endpoints.add(r.dst_lo)
        dst_endpoints.add(r.dst_hi)
    
    return sorted(src_endpoints), sorted(dst_endpoints)

def count_cells_for_proto(rules: List[IPRule], proto: int) -> Dict:
    """Count intersection cells for a specific protocol using grid decomposition"""
    proto_rules = [r for r in rules if r.proto == proto]
    
    if len(proto_rules) < 2:
        return {
            'proto': proto,
            'num_rules': len(proto_rules),
            'pairwise_intersections': 0,
            'proper_intersections': 0,
            'grid_cells': 0,
            'intersection_cells': 0,
            'valid_cells': 0,
            'expansion_ratio': 0
        }
    
    # Count pairwise intersections
    pairwise_count = 0
    proper_count = 0
    for i, a in enumerate(proto_rules):
        for b in proto_rules[i+1:]:
            if rules_intersect(a, b):
                pairwise_count += 1
                if is_proper_intersection(a, b):
                    proper_count += 1
    
    # Build elementary intervals (grid decomposition)
    src_ep, dst_ep = build_elementary_intervals(rules, proto)
    
    total_grid_cells = (len(src_ep) - 1) * (len(dst_ep) - 1) if len(src_ep) > 1 and len(dst_ep) > 1 else 0
    
    # Count cells covered by >= 2 rules (intersection cells)
    intersection_cells = 0
    valid_cells = 0  # Cells with >= 2 "proper intersecting" rules
    
    for si in range(len(src_ep) - 1):
        cell_src_lo = src_ep[si]
        cell_src_hi = src_ep[si + 1]
        
        for dj in range(len(dst_ep) - 1):
            cell_dst_lo = dst_ep[dj]
            cell_dst_hi = dst_ep[dj + 1]
            
            # Count rules covering this cell
            covering_rules = []
            for r in proto_rules:
                if (r.src_lo <= cell_src_lo and cell_src_hi <= r.src_hi and
                    r.dst_lo <= cell_dst_lo and cell_dst_hi <= r.dst_hi):
                    covering_rules.append(r)
            
            if len(covering_rules) >= 2:
                intersection_cells += 1
                
                # C++ algorithm optimization: check "minimal" - rules that properly intersect
                minimal_count = 0
                for i, r1 in enumerate(covering_rules):
                    has_proper = False
                    for r2 in covering_rules:
                        if r1.idx != r2.idx and is_proper_intersection(r1, r2):
                            has_proper = True
                            break
                    if has_proper:
                        minimal_count += 1
                
                # Only count if >= 2 rules have proper intersection
                if minimal_count >= 2:
                    valid_cells += 1
    
    return {
        'proto': proto,
        'proto_name': {6: 'TCP', 17: 'UDP', 1: 'ICMP', 0: 'HOPOPT'}.get(proto, str(proto)),
        'num_rules': len(proto_rules),
        'src_endpoints': len(src_ep),
        'dst_endpoints': len(dst_ep),
        'pairwise_intersections': pairwise_count,
        'proper_intersections': proper_count,
        'grid_cells': total_grid_cells,
        'intersection_cells': intersection_cells,
        'valid_cells': valid_cells,
        'expansion_ratio': intersection_cells / proper_count if proper_count > 0 else 0
    }

def analyze_cell_expansion(rules: List[IPRule]) -> None:
    """Analyze why cells expand from pairwise intersections"""
    
    print("=" * 80)
    print("Intersection Cell 膨胀分析")
    print("=" * 80)
    print()
    
    # Group by protocol
    protos = sorted(set(r.proto for r in rules))
    
    total_proper = 0
    total_cells = 0
    
    print("【核心概念】")
    print("-" * 80)
    print("Python分析的'相交对'：检查每对规则是否有交集，计数关系数量")
    print("C++算法的'交集单元格'：将所有规则边界进行网格分解，统计被>=2条规则覆盖的单元格")
    print()
    print("【膨胀原因示意】")
    print("-" * 80)
    print("假设3条规则 A, B, C 两两相交：")
    print("  - 成对分析: A∩B, A∩C, B∩C → 3 对")
    print("  - 网格分解后可能产生 9+ 个单元格，其中多个是交集单元格")
    print()
    
    print("【按协议分析】")
    print("-" * 80)
    print(f"{'协议':<10} {'规则数':<8} {'成对相交':<10} {'真正相交':<10} "
          f"{'简单网格':<10} {'有效单元格':<12} {'膨胀比':<8}")
    print("-" * 80)
    
    for proto in protos:
        result = count_cells_for_proto(rules, proto)
        total_proper += result['proper_intersections']
        total_cells += result['valid_cells']
        
        print(f"{result['proto_name']:<10} {result['num_rules']:<8} "
              f"{result['pairwise_intersections']:<10} "
              f"{result['proper_intersections']:<10} "
              f"{result['intersection_cells']:<10} "
              f"{result['valid_cells']:<12} "
              f"{result['valid_cells']/result['proper_intersections'] if result['proper_intersections'] > 0 else 0:.2f}x")
    
    print("-" * 80)
    print(f"{'合计':<10} {len(rules):<8} {'':<10} "
          f"{total_proper:<10} {'':<10} {total_cells:<12} "
          f"{total_cells/total_proper if total_proper > 0 else 0:.2f}x")
    print()
    
    print("【关键解释】")
    print("-" * 80)
    print(f"1. 真正相交的规则对 (proper intersection): {total_proper} 对")
    print(f"   这些是部分重叠但非包含关系的规则对")
    print()
    print(f"2. 经过优化后的有效交集单元格: {total_cells} 个")
    print(f"   只统计'minimal'规则数 >= 2 的单元格")
    print(f"   (排除了完全包含关系导致的冗余单元格)")
    print()
    print(f"3. 最终膨胀比例: {total_cells/total_proper if total_proper > 0 else 0:.2f}x")
    print()
    print("【C++算法的三重优化】")
    print("-" * 80)
    print("优化1: 'minimal' 规则筛选")
    print("   - 对每个单元格，只保留与其他规则'真正相交'的规则")
    print("   - 排除纯粹的包含/被包含关系")
    print("   - 如果 minimal < 2，该单元格被丢弃")
    print()
    print("优化2: 连续区域合并 (rebuild_continuous_cells)")
    print("   - 相邻的、具有相同覆盖规则的单元格会被合并")
    print("   - 大幅减少最终单元格数量")
    print()
    print("优化3: 祖先关系去重")
    print("   - 如果所有覆盖规则都能通过一个'祖先'规则解释")
    print("   - 则该单元格是冗余的，被丢弃")
    print()
    print("【为什么会膨胀？】")
    print("-" * 80)
    print("关键在于 '多重覆盖'：")
    print("- 当规则 A, B, C 在某个区域都有覆盖时，该区域会被切割成多个单元格")
    print("- 每个单元格都被 >= 2 条规则覆盖，所以都算作交集单元格")
    print("- 但这些单元格来自相同的几对规则的重叠区域")
    print()
    print("举例：如果 A∩B 的区域被 C 的边界切割成 4 部分，就产生 4 个交集单元格")
    print("但本质上这 4 个单元格都属于 A∩B 这一对相交关系")
    
def main():
    filepath = os.path.join(os.path.dirname(__file__), 'src', 'output', 'merged_ip_table.txt')
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        print("Please run HyperLens first to generate merged_ip_table.txt")
        sys.exit(1)
    
    print(f"Loading: {filepath}")
    rules = load_merged_ip_table(filepath)
    print(f"Loaded {len(rules)} rules")
    print()
    
    analyze_cell_expansion(rules)

if __name__ == '__main__':
    main()
