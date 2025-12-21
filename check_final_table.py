#!/usr/bin/env python3
"""
分析 final_ip_table_cidr.txt，检查：
1. cell 部分的 G-ID 是否相同
2. Merged 部分（non-leaders）顺序是否变化
3. Rmax 部分（leaders）G-ID 是否只有一个且不变
"""

def parse_final_table(filename):
    """解析 final_ip_table_cidr.txt"""
    rules = []
    with open(filename, 'r') as f:
        lines = f.readlines()
        for i, line in enumerate(lines[1:], 1):  # 跳过标题行
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            priority = int(parts[0])
            src = parts[1]
            dst = parts[2]
            proto = int(parts[3])
            # GIDs 可能在 parts[4] 或之后（因为可能有空格）
            gids_str = ' '.join(parts[4:]) if len(parts) > 4 else ""
            # 移除所有空格后按逗号分割
            gids_str_clean = gids_str.replace(' ', '')
            gids = [int(x) for x in gids_str_clean.split(',') if x] if gids_str_clean else []
            
            rules.append({
                'index': i - 1,  # 0-based
                'priority': priority,
                'src': src,
                'dst': dst,
                'proto': proto,
                'gids': gids,
                'gid_count': len(gids)
            })
    return rules

def analyze_table(rules):
    """分析表格结构"""
    print("=" * 80)
    print("Final IP Table Analysis")
    print("=" * 80)
    
    # 根据 G-ID 数量分类
    cells_and_merged = []  # G-ID 数量 >= 2 (cells 和 non-leaders)
    rmax_leaders = []      # G-ID 数量 == 1 (leaders)
    
    for rule in rules:
        if rule['gid_count'] >= 2:
            cells_and_merged.append(rule)
        elif rule['gid_count'] == 1:
            rmax_leaders.append(rule)
    
    print(f"\n总规则数: {len(rules)}")
    print(f"Cells + Merged (G-ID >= 2): {len(cells_and_merged)}")
    print(f"Rmax Leaders (G-ID == 1): {len(rmax_leaders)}")
    
    # 分析 Rmax Leaders
    print("\n" + "=" * 80)
    print("Rmax Leaders (G-ID == 1):")
    print("=" * 80)
    for rule in rmax_leaders:
        print(f"  Index {rule['index']:2d}: {rule['src']:20s} {rule['dst']:20s} proto={rule['proto']:2d} G-ID={rule['gids']}")
    
    # 分析 Cells + Merged
    print("\n" + "=" * 80)
    print("Cells + Merged (G-ID >= 2) - 前10条:")
    print("=" * 80)
    for rule in cells_and_merged[:10]:
        print(f"  Index {rule['index']:2d}: {rule['src']:20s} {rule['dst']:20s} proto={rule['proto']:2d} G-ID={rule['gids']}")
    
    if len(cells_and_merged) > 10:
        print(f"  ... (还有 {len(cells_and_merged) - 10} 条)")
    
    # 检查 G-ID 模式
    print("\n" + "=" * 80)
    print("G-ID 模式分析:")
    print("=" * 80)
    
    # 统计每个 G-ID 出现的次数
    gid_usage = {}
    for rule in rules:
        for gid in rule['gids']:
            gid_usage[gid] = gid_usage.get(gid, 0) + 1
    
    # 找出 Rmax leader 的 G-ID（只出现一次的）
    rmax_gids = [gid for gid, count in gid_usage.items() if count == 1]
    print(f"Rmax Leader G-IDs (只出现一次): {sorted(rmax_gids)}")
    
    # 检查 cells_and_merged 中的第二个 G-ID 是否都是 Rmax leader
    second_gids = []
    for rule in cells_and_merged:
        if len(rule['gids']) >= 2:
            second_gids.append(rule['gids'][1])
    
    unique_second_gids = sorted(set(second_gids))
    print(f"Cells/Merged 中的第二个 G-ID (应该都是 Rmax leader): {unique_second_gids}")
    
    # 验证
    if set(unique_second_gids) == set(rmax_gids):
        print("✓ 验证通过：所有第二个 G-ID 都是 Rmax leader")
    else:
        print("✗ 验证失败：部分第二个 G-ID 不是 Rmax leader")
        print(f"  差异: {set(unique_second_gids) - set(rmax_gids)}")

if __name__ == "__main__":
    import sys
    filename = "src/output/final_ip_table_cidr.txt"
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    
    rules = parse_final_table(filename)
    analyze_table(rules)

