# P4Lens 主文件重构总结

## 概述
成功将 P4Lens 项目重构为以单一 `P4Lens.cpp` 为主入口的结构，提高了代码组织性和可维护性。

## 主要改动

### 1. 创建新主入口文件
- **文件**: `src/P4Lens.cpp` (新建)
- **作用**: 统一的程序入口点
- **功能**:
  - 解析命令行参数（ACL 规则文件路径）
  - 协调加载规则、拆分、合并、元数据生成、表生成等各个处理步骤
  - 提供清晰的处理流程输出

### 2. 保护其他源文件中的 main 函数
为了兼容性和条件编译，为所有其他 main 函数添加了 `#ifdef` 保护：

#### a. `src/Parallel-Port-Lookup.cpp`
- 添加 `#ifdef COMPILE_AS_STANDALONE_MAIN` ... `#endif` 包装主函数
- 保留原有的 main 实现，以供独立编译时使用

#### b. `src/input.cpp`
- 原有的 `#ifdef DEMO_LOADER_MAIN` ... `#endif` 保持不变

#### c. `src/Dependent-Set-Prefix-Lookup.cpp`
- 原有的 `#ifdef DEMO_LOADER_MAIN` ... `#endif` 保持不变

### 3. 更新头文件
- **文件**: `src/Parallel-Port-Lookup.hpp`
- **改动**: 添加函数声明
  ```cpp
  void laod_and_create_IP_table(...);
  void create_Table_for_port(...);
  ```

### 4. 更新编译脚本
- **文件**: `build_and_run.sh`
- **改动**:
  - 编译输出从 `src/Parallel-Port-Lookup` 改为 `src/P4Lens`
  - 编译命令中将 `src/P4Lens.cpp` 作为第一个源文件
  - 移除 `-DCOMPILE_AS_LIB` 标志（因为现在有明确的 main 函数）
  - 更新输出文件检查以包含所有生成的表文件

## 工作流程

### 编译流程
```bash
g++-11 -std=c++17 \
    src/P4Lens.cpp \
    src/Parallel-Port-Lookup.cpp \
    src/input.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/P4Lens
```

### 程序执行流程
```
P4Lens.cpp (main)
    ├─ load_rules_from_file()
    ├─ split_rules()
    ├─ merge_same_ip_entry()
    ├─ laod_and_create_IP_table()
    │   └─ ... (IP 表和元数据生成)
    └─ create_Table_for_port()
        ├─ split_port_range_into_blocks_for_src()
        ├─ split_port_range_into_blocks_for_dst()
        └─ (SRC/DST TCAM/SRAM 表生成)
```

## 生成的输出文件

| 文件名 | 说明 |
|------|------|
| `final_ip_table_cidr.txt` | 最终 IP 表（CIDR 格式） |
| `meta_merged.txt` | 合并后的元数据 |
| `SRC_TCAM_Table.txt` | 源端口 TCAM 表 |
| `SRC_SRAM_Table.txt` | 源端口 SRAM 表 |
| `DST_TCAM_Table.txt` | 目标端口 TCAM 表 |
| `DST_SRAM_Table.txt` | 目标端口 SRAM 表 |

## 验证结果

✓ 编译成功（无错误，仅有一条非关键警告）
✓ 程序正常运行
✓ 所有输出文件正确生成
✓ Action 字段正确传递并输出
✓ SRC 和 DST 表数据正确生成

## 向后兼容性

- 所有核心功能保持不变
- Action 字段传递链保持完整
- 各源文件中的原有 main 函数被条件编译保护，未被删除
- 可通过重新编译（使用 `-DCOMPILE_AS_STANDALONE_MAIN` 或 `-DDEMO_LOADER_MAIN`）执行原有 main 函数

## 后续建议

1. **添加日志级别控制**: 可以添加命令行参数控制输出详度
2. **配置文件支持**: 可考虑支持配置文件而非仅命令行参数
3. **模块化构建**: 可进一步拆分成静态库和主程序
4. **完整测试套件**: 添加自动化测试确保各模块功能正确
5. **文档完善**: 详细记录各模块接口和数据结构

