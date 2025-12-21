# 重排逻辑说明

## 问题分析

用户观察到：`final_ip_table` 中 index 7 的规则 `10.0.0.0/8 0.0.0.0/0` 应该参与重排，但似乎没有参与。

## 实际情况

### 1. 重排确实发生了

从调试输出可以看到：
- Proto 6 重排后：`old_idx=0(ancestors=0) old_idx=1(ancestors=1) old_idx=7(ancestors=1) ...`
- `old_idx=1` 对应的是 `10.0.0.0/8 0.0.0.0/0`（在 `Rmax_merged_ip_table` 中的原始位置）
- 重排后，它在 `RO_merged_ip_table` 中的位置是 1（ancestors=1，排在 ancestors=0 之后）

### 2. final_ip_table 的结构

- **Index 0-6**: intersections (cells) - 7个
- **Index 7+**: merged rules (non-leaders 和 leaders)
  - Index 7 的规则来自 `RO_merged_ip_table[1]`
  - 这个规则确实参与了重排（从原始位置 1 重排到新位置 1）

### 3. 排序逻辑

重排按照 **ancestors 数量从少到多** 排序：
- ancestors=0 的规则（覆盖范围最大）排在前面
- ancestors=1 的规则排在后面
- 以此类推

`10.0.0.0/8 0.0.0.0/0` 有 1 个 ancestor，所以排在 ancestors=0 的规则之后，这是**正确的**。

## 结论

**程序逻辑正确**：
1. ✅ 重排确实发生了
2. ✅ Index 7 的规则来自重排后的 `RO_merged_ip_table[1]`
3. ✅ 排序逻辑正确（按 ancestors 数量从少到多）

用户可能误解了重排的含义。重排是按照 ancestors 数量排序，而不是按照覆盖的规则数量排序。一个规则覆盖很多规则，意味着它的 ancestors 很少（因为很少有规则能覆盖它），所以应该排在前面。

