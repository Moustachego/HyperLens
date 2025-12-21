# 重排索引映射修正的必要性 - 详细例子

## 场景设置

假设我们有 5 条规则，经过 Rmax 处理后：

### 重排前的 Rmax_merged_ip_table（原始顺序）

```
索引 | 规则内容        | rmax_id | 说明
-----|----------------|---------|------
0    | Rule A (proto=6)| 0       | Leader（覆盖 Rule 1, 2）
1    | Rule B (proto=6)| 0       | 非 Leader，被 Rule 0 覆盖
2    | Rule C (proto=6)| 0       | 非 Leader，被 Rule 0 覆盖
3    | Rule D (proto=6)| 3       | Leader（覆盖 Rule 4）
4    | Rule E (proto=6)| 3       | 非 Leader，被 Rule 3 覆盖
```

**关键点：**
- Rule 0 是 Leader，`rmax_id = 0`（指向自己）
- Rule 1, 2 的 `rmax_id = 0`（指向它们的 Leader Rule 0）
- Rule 3 是 Leader，`rmax_id = 3`（指向自己）
- Rule 4 的 `rmax_id = 3`（指向它的 Leader Rule 3）

### 假设的 ancestors 数量（用于排序）

假设经过 `build_ancestors_for_subset` 计算后：
- Rule 0: ancestors.size() = 0（没有祖先，覆盖范围最大）
- Rule 1: ancestors.size() = 1（Rule 0 是它的祖先）
- Rule 2: ancestors.size() = 1（Rule 0 是它的祖先）
- Rule 3: ancestors.size() = 0（没有祖先）
- Rule 4: ancestors.size() = 1（Rule 3 是它的祖先）

### 重排后的 RO_merged_ip_table（按 ancestors 从少到多排序）

```
新索引 | 旧索引 | 规则内容        | rmax_id（未修正）| rmax_id（修正后）| 说明
-------|--------|----------------|-----------------|-----------------|------
0      | 0      | Rule A (proto=6)| 0               | 0               | Leader，正确
1      | 3      | Rule D (proto=6)| 3               | 1               | Leader，需要修正！
2      | 1      | Rule B (proto=6)| 0               | 0               | 非 Leader，正确
3      | 2      | Rule C (proto=6)| 0               | 0               | 非 Leader，正确
4      | 4      | Rule E (proto=6)| 3               | 1               | 非 Leader，需要修正！
```

## 问题 1：Leader 判断失效

在 `merge_cells_and_ip_table` 函数中（第 1021 行）：

```cpp
for (size_t i = 0; i < N; ++i) {
    if (OR_merged_ip_table[i].rmax_id == i)  // 判断是否为 Leader
        leader_indices.push_back(i);
    else
        nonleader_indices.push_back(i);
}
```

### ❌ 如果不修正索引映射：

```cpp
// 检查新索引 1 的规则（Rule D）
if (RO_merged_ip_table[1].rmax_id == 1)  // 3 == 1? ❌ 错误！
    // 不会识别为 Leader，导致 Rule D 被错误地当作非 Leader 处理
```

**结果：**
- Rule D（新索引 1）的 `rmax_id = 3`，但 `3 != 1`，所以不会被识别为 Leader
- Rule D 会被错误地放入 `nonleader_indices`
- 最终输出中，Rule D 可能不会被正确标记为 `is_rmax = true`

### ✅ 修正后：

```cpp
// Rule D 的 rmax_id 被更新为 1（新索引）
if (RO_merged_ip_table[1].rmax_id == 1)  // 1 == 1? ✅ 正确！
    // 正确识别为 Leader
```

## 问题 2：非 Leader 规则指向错误的 Leader

### ❌ 如果不修正索引映射：

```cpp
// Rule E（新索引 4）的 rmax_id = 3（旧索引）
// 但在新数组中，索引 3 是 Rule C，不是 Rule D（Leader）！

// 在 merge_cells_and_ip_table 中查找 Leader：
size_t leader_idx = Rule E.rmax_id;  // = 3
if (RO_merged_ip_table[3].rmax_id == 3)  // Rule C 的 rmax_id = 0，0 != 3 ❌
    // 找不到 Leader，Rule E 的 group_ids 可能错误
```

**结果：**
- Rule E 的 `rmax_id = 3` 指向新数组中的 Rule C
- 但 Rule C 不是 Leader（它的 `rmax_id = 0`）
- 导致 Rule E 无法找到正确的 Leader，G-ID 分配错误

### ✅ 修正后：

```cpp
// Rule E 的 rmax_id 被更新为 1（指向 Rule D 的新索引）
size_t leader_idx = Rule E.rmax_id;  // = 1
if (RO_merged_ip_table[1].rmax_id == 1)  // Rule D 的 rmax_id = 1，1 == 1 ✅
    // 正确找到 Leader Rule D
```

## 问题 3：IntersectionCell 中的 rmax_id 失效

假设有一个 IntersectionCell：

```cpp
IntersectionCell cell;
cell.rmax_id = 3;  // 指向旧索引 3（Rule D）
```

### ❌ 如果不更新 cell.rmax_id：

```cpp
// 在 merge_cells_and_ip_table 中：
if (cell.rmax_id < OR_merged_ip_table.size() &&  // 3 < 5 ✅
    OR_merged_ip_table[cell.rmax_id].rmax_id == cell.rmax_id)  // Rule C 的 rmax_id = 0，0 != 3 ❌
    // 找不到 Leader，cell 的 group_ids 可能错误
```

### ✅ 更新后：

```cpp
// cell.rmax_id 被更新为 1（Rule D 的新索引）
if (cell.rmax_id < OR_merged_ip_table.size() &&  // 1 < 5 ✅
    OR_merged_ip_table[cell.rmax_id].rmax_id == cell.rmax_id)  // Rule D 的 rmax_id = 1，1 == 1 ✅
    // 正确找到 Leader
```

## 完整的修正流程示例

### 步骤 1：重排并建立映射

```cpp
old_to_new_idx = {
    0 -> 0,  // Rule A: 旧索引 0 -> 新索引 0
    1 -> 2,  // Rule B: 旧索引 1 -> 新索引 2
    2 -> 3,  // Rule C: 旧索引 2 -> 新索引 3
    3 -> 1,  // Rule D: 旧索引 3 -> 新索引 1 ⚠️ 关键！
    4 -> 4   // Rule E: 旧索引 4 -> 新索引 4
}
```

### 步骤 2：更新 RO_merged_ip_table 中的 rmax_id

```cpp
// Rule D（新索引 1）
old_rmax_id = 3;  // 旧值
if (old_rmax_id == 3) {  // 是 Leader
    RO_merged_ip_table[1].rmax_id = 1;  // 更新为新索引
}

// Rule E（新索引 4）
old_rmax_id = 3;  // 指向旧 Leader Rule D
auto it = proto_old_to_new.find(3);  // 找到映射：3 -> 1
RO_merged_ip_table[4].rmax_id = 1;  // 更新为 Leader 的新索引
```

### 步骤 3：更新 IntersectionCell 中的 rmax_id

```cpp
// 对于所有 cells
for (auto& cell : intersections) {
    if (cell.rmax_id == 3) {  // 指向旧 Rule D
        cell.rmax_id = old_to_new_idx[3];  // = 1
    }
}
```

## 总结

**修正的必要性：**

1. **Leader 识别**：确保 `rmax_id == 新索引` 的判断能正确识别 Leader
2. **Leader 查找**：确保非 Leader 规则能通过 `rmax_id` 找到正确的新 Leader 位置
3. **Cell 关联**：确保 IntersectionCell 能正确关联到重排后的 Leader
4. **G-ID 分配**：确保最终的 group_ids 正确，不会出现负数、空值或越界

**如果不修正，会导致：**
- 规则被错误分类（Leader 被当作非 Leader）
- G-ID 分配错误
- 最终输出表的结构不正确
- 可能触发断言失败或运行时错误

