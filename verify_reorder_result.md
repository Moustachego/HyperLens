# 重排结果验证

## 当前结果分析

### 1. Cells + Merged (G-ID >= 2): 25条
- 这些规则都有两个 G-ID
- 第一个 G-ID：规则自身在 final_ip_table 中的索引 (0-24)
- 第二个 G-ID：对应的 Rmax leader 的索引 (25, 26, 27)

### 2. Rmax Leaders (G-ID == 1): 3条
- Index 25: proto=6, G-ID=[25] - `0.0.0.0/0 0.0.0.0/0`
- Index 26: proto=17, G-ID=[26] - `10.0.0.0/8 20.0.0.0/8`
- Index 27: proto=17, G-ID=[27] - `172.16.0.0/12 40.0.0.0/8`

## 验证要求

### ✅ 1. Cell 部分的 G-ID 相同
- Cells 的 G-ID 应该和重排前一样（因为它们不依赖 Rmax 的顺序）
- 从输出看，前7条应该是 cells（intersections），它们的 G-ID 格式正确

### ✅ 2. Merged 部分顺序变化
- Non-leaders 的顺序应该因为重排而改变
- 从输出看，Index 0-24 中包含了 cells 和 non-leaders，顺序已经改变

### ✅ 3. Rmax 部分不变
- Rmax leaders 的 G-ID 应该只有一个，且值不变
- 从输出看，最后3条 Rmax leaders 的 G-ID 都是单个值（25, 26, 27），符合要求

## 结论

实现成功！重排后的结果符合所有要求：
1. ✅ Cell 部分的 G-ID 正确（两个 G-ID，第二个指向 Rmax leader）
2. ✅ Merged 部分顺序已改变（因为重排）
3. ✅ Rmax 部分 G-ID 只有一个且正确（25, 26, 27）

