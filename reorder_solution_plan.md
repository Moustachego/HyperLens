# 重排后索引映射解决方案

## 问题分析

### 当前状态
1. **`Rmax_merged_ip_table`** (重排前):
   - 索引: `0, 1, 2, ...`
   - `rmax_id`: 指向 leader 在 `Rmax_merged_ip_table` 中的索引
   - `ancestors`: 存储的是 `Rmax_merged_ip_table` 的索引

2. **`RO_merged_ip_table`** (重排后):
   - 索引: `0, 1, 2, ...` (但顺序变了)
   - `rmax_id`: **仍然是旧索引** (指向 `Rmax_merged_ip_table`)
   - `ancestors`: **仍然是旧索引** (指向 `Rmax_merged_ip_table`)

3. **`intersections` 和 `Rmax_intersections`**:
   - `rmax_id`: 指向 `Rmax_merged_ip_table` 的旧索引

### 核心问题
- `merge_cells_and_ip_table` 使用 `RO_merged_ip_table`，但：
  - 判断 leader 时：`OR_merged_ip_table[i].rmax_id == i` 会失败（`rmax_id` 是旧索引，`i` 是新索引）
  - 访问 `OR_merged_ip_table[cell.rmax_id]` 可能越界或访问错误位置
- `Create_Metainfo_for_port` 中：
  - `ancestors` 的索引需要保持为 `Rmax_merged_ip_table` 的旧索引（因为后续处理需要）

## 解决方案

### 核心思路：**分离关注点**
- **`rmax_id`**: 需要映射到新索引（因为用于访问 `RO_merged_ip_table`）
- **`ancestors`**: 保持旧索引（因为后续端口处理需要）

### 实现步骤

#### Step 1: 在 `Reorder_merged_ip_table` 中建立索引映射
```cpp
void Reorder_merged_ip_table(
    std::vector<Rmax_IPRule>& Rmax_merged_ip_table,
    std::vector<Rmax_IPRule>& RO_merged_ip_table,
    std::unordered_map<size_t, size_t>& old_to_new_idx  // 新增：旧索引 → 新索引
)
```

**逻辑**：
- 建立 `old_to_new_idx` 映射：`Rmax_merged_ip_table[old_idx]` → `RO_merged_ip_table[new_idx]`
- 更新 `RO_merged_ip_table` 中每个规则的 `rmax_id`：从旧索引映射到新索引
- **不修改 `ancestors`**：保持为 `Rmax_merged_ip_table` 的旧索引

#### Step 2: 更新 cells 的 `rmax_id`
在 `load_and_create_IP_table` 中，重排后：
```cpp
// 更新 intersections 和 Rmax_intersections 的 rmax_id
for (auto& cell : intersections) {
    if (cell.rmax_id != SIZE_MAX) {
        auto it = old_to_new_idx.find(cell.rmax_id);
        if (it != old_to_new_idx.end()) {
            cell.rmax_id = it->second;  // 映射到新索引
        }
    }
}
// 同样处理 Rmax_intersections
```

#### Step 3: `merge_cells_and_ip_table` 正常工作
- `OR_merged_ip_table[i].rmax_id == i` 现在可以正确判断 leader
- `OR_merged_ip_table[cell.rmax_id]` 可以正确访问

#### Step 4: `Create_Metainfo_for_port` 使用旧索引
- `RO_merged_ip_table[i].ancestors` 中的索引仍然是 `Rmax_merged_ip_table` 的旧索引
- 如果需要访问 `ancestors` 指向的规则，需要：
  - 方案A：通过 `old_to_new_idx` 映射到新索引，访问 `RO_merged_ip_table`
  - 方案B：直接访问 `Rmax_merged_ip_table`（如果还保留的话）

## 关键点总结

1. **`rmax_id` 映射**：重排后必须映射到新索引，因为用于访问 `RO_merged_ip_table`
2. **`ancestors` 保持旧索引**：因为后续端口处理逻辑依赖旧索引
3. **索引映射表**：`old_to_new_idx` 是关键，需要传递给需要的地方
4. **cells 更新**：`intersections` 和 `Rmax_intersections` 的 `rmax_id` 需要更新

## 代码修改点

1. **`Reorder_merged_ip_table`**:
   - 添加 `old_to_new_idx` 参数
   - 建立映射
   - 更新 `RO_merged_ip_table` 中规则的 `rmax_id`

2. **`load_and_create_IP_table`**:
   - 接收 `old_to_new_idx`
   - 更新 cells 的 `rmax_id`

3. **`Create_Metainfo_for_port`** (如果需要):
   - 接收 `old_to_new_idx` 和 `Rmax_merged_ip_table`（如果需要访问 ancestors）

