# 祖先规则端口映射方案

## 需求

对于 Merged 部分优先级高的规则（ancestors 多的），需要把它的祖先（ancestors）的端口对也映射到对应的 G-ID 中。

## 实现方案

### 1. 修改函数签名

**`Generate_MergedR_GID_to_metaifno`**:
- 添加 `RO_merged_ip_table` 参数：用于访问重排后的规则及其 ancestors
- 添加 `old_to_new_idx` 参数：用于将 ancestors 的旧索引映射到新索引

**`Create_Metainfo_for_port`**:
- 添加 `RO_merged_ip_table` 和 `old_to_new_idx` 参数
- 传递给 `Generate_MergedR_GID_to_metaifno`

### 2. 核心逻辑

在 `Generate_MergedR_GID_to_metaifno` 中：

1. **处理规则自己的原始规则**（原有逻辑）：
   - 遍历 `fr.merged_R`，添加端口对

2. **处理祖先规则的原始规则**（新增逻辑）：
   - 通过 `fr.original_merged_index` 获取 `RO_merged_ip_table` 中的规则
   - 遍历规则的 `ancestors`（旧索引）
   - 通过 `old_to_new_idx` 将旧索引映射到新索引
   - 获取祖先规则的 `merged_R`
   - 为每个祖先规则的原始规则添加端口对

### 3. 去重机制

使用 `seen_in_gid` 集合在同一个 G-ID 内部去重，确保相同的端口对不会重复添加。

## 关键点

1. **索引映射**：
   - `fr.original_merged_index` 是 `RO_merged_ip_table` 的新索引
   - `ancestors` 存储的是 `Rmax_merged_ip_table` 的旧索引
   - 需要通过 `old_to_new_idx` 映射到新索引

2. **端口对来源**：
   - 规则自己的 `merged_R` → 端口对
   - 祖先规则的 `merged_R` → 端口对（新增）

3. **去重**：
   - 在同一个 G-ID 内部，相同的端口对（Src_lo, Src_hi, Dst_lo, Dst_hi）只添加一次

## 效果

现在每个 G-ID 对应的端口对包括：
- ✅ 规则自己的原始规则的端口对
- ✅ 规则的所有祖先规则的原始规则的端口对

这样，优先级高的规则（ancestors 多的）会包含更多祖先的端口对，实现需求。

