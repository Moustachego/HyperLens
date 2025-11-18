# 🎯 P4lens Parallel-Port-Lookup 完整使用指南

## ✅ 当前状态

**所有编译和运行都成功了！** 程序已验证可以：
- ✓ 编译成功（所有三个源文件链接）
- ✓ 加载规则文件（27 条规则）
- ✓ 处理 IP 和端口数据
- ✓ 生成输出文件

---

## 🚀 三种使用方法

### 方法 1：VS Code UI（推荐）✨

**编译**：按 `Ctrl+Shift+B`
- 自动运行 "Build: Parallel-Port-Lookup (g++-11)" 任务
- 链接所有必需的源文件

**调试运行**：按 `F5`
- 自动编译（如需要）
- 启动 GDB 调试器
- 自动传递规则文件参数

**优点**：
- 图形界面，直观
- 支持断点调试
- 自动处理依赖关系

---

### 方法 2：自动脚本（最简单）🤖

在项目根目录运行：
```bash
bash build_and_run.sh
```

**脚本会自动**：
1. 清理旧的二进制文件
2. 编译（三个源文件）
3. 验证二进制文件
4. 运行程序
5. 检查输出文件

**优点**：
- 一行命令完成所有操作
- 自动清理和验证
- 显示详细的进度信息

---

### 方法 3：手动命令行（灵活）💻

```bash
cd /home/long/Desktop/P4lens

# 编译
/usr/bin/g++-11 -std=c++17 -g -DCOMPILE_AS_LIB \
    src/Parallel-Port-Lookup.cpp \
    src/input.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/Parallel-Port-Lookup

# 运行（使用默认规则文件）
./src/Parallel-Port-Lookup src/ACL_rules/test.rules

# 或运行其他规则文件
./src/Parallel-Port-Lookup src/ACL_rules/acl_10k.rules
./src/Parallel-Port-Lookup src/ACL_rules/acl_100k.rules
```

**优点**：
- 完全控制编译参数
- 可以使用任何规则文件
- 最灵活的方式

---

## 📂 可用的规则文件

所有规则文件位于 `src/ACL_rules/` 目录：

| 文件名 | 规则数量 | 用途 |
|--------|---------|------|
| `test.rules` | 27 | 快速测试 |
| `test1.rules` | 多 | 另一个测试集 |
| `acl_10k.rules` | 10,000 | 中等规模 |
| `acl_100k.rules` | 100,000 | 大规模测试 |
| `acl_10k_1.rules` | 10,000 | 另一个 10K 集 |
| `acl_100k_2.rules` | 100,000 | 另一个 100K 集 |
| `fw1_100k_0.8.rules` | 100,000 | 防火墙规则 |

---

## 📊 程序输出说明

程序运行后会生成以下文件：

### `final_ip_table_cidr.txt`
最终的 IP 规则表（CIDR 格式）
- 包含所有处理后的 IP 规则
- 一行一条规则

### `meta_src_debug.txt`
调试信息文件
- 源端口的元信息
- 用于调试和分析

### 控制台输出
程序运行时的详细日志：
```
[Parallel-Port-Lookup] Loaded 27 rules from 'src/ACL_rules/test.rules'
[split_rules] IP table size = 27, Port table size = 27
[merge_same_ip_entry] Original IP rules = 27, merged = 21
[find_Rmax_for_merged_ip_table] Rmax rules filled for 21 entries
...
[RESULT] total distinct blocks = 2048, assigned blocks = 2048, TCAM entries = 1
[Parallel-Port-Lookup] SRC port TCAM table built with 1 entries
```

---

## 🔧 项目结构

```
src/
├── Parallel-Port-Lookup.cpp       ← 主程序（port lookup 逻辑）
├── Parallel-Port-Lookup.hpp       ← 数据结构定义
├── Parallel-Port-Lookup           ← 编译后的可执行文件
├── input.cpp                      ← 规则加载功能
├── input.hpp                      ← 规则加载声明
├── Dependent-Set-Prefix-Lookup.cpp    ← IP 处理功能（main 被注释）
├── Dependent-Set-Prefix-Lookup.hpp    ← IP 处理声明
└── ACL_rules/                     ← 规则文件目录
    ├── test.rules
    ├── acl_10k.rules
    ├── acl_100k.rules
    └── ... 其他规则文件

.vscode/
├── tasks.json                     ← 编译任务配置
└── launch.json                    ← 调试配置

build_and_run.sh                   ← 自动编译运行脚本
BUILD_AND_DEBUG.md                 ← 基本指南
BUILD_FIX_EXPLANATION.md           ← 问题修复说明
```

---

## ⚙️ 编译标志说明

| 标志 | 说明 |
|------|------|
| `-std=c++17` | 使用 C++17 标准 |
| `-g` | 包含调试符号（支持 GDB） |
| `-DCOMPILE_AS_LIB` | 禁用 Dependent-Set-Prefix-Lookup.cpp 中的 main() |
| `-fdiagnostics-color=always` | 彩色编译输出 |

**关键点**：`-DCOMPILE_AS_LIB` 宏非常重要，它防止多个 main() 函数符号冲突。

---

## 🎯 快速参考

### 最快的方式（一行命令）
```bash
bash /home/long/Desktop/P4lens/build_and_run.sh
```

### VS Code 方式（按键）
| 快捷键 | 操作 |
|--------|------|
| `Ctrl+Shift+B` | 编译 |
| `F5` | 编译 + 调试运行 |

### 手动方式（完全控制）
```bash
cd /home/long/Desktop/P4lens
/usr/bin/g++-11 -std=c++17 -g -DCOMPILE_AS_LIB \
    src/Parallel-Port-Lookup.cpp src/input.cpp src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/Parallel-Port-Lookup
./src/Parallel-Port-Lookup src/ACL_rules/acl_10k.rules
```

---

## ❓ 常见问题

### Q: 编译出现 "undefined reference" 错误
**A**: 确保：
1. 三个源文件都被包含在编译命令中
2. `-DCOMPILE_AS_LIB` 标志已设置
3. 所有源文件都在 `src/` 目录中

### Q: 程序运行但输出为空
**A**: 检查：
1. 规则文件路径正确（`src/ACL_rules/xxx.rules`）
2. 规则文件确实存在：`ls src/ACL_rules/`
3. 规则文件不为空

### Q: VS Code 的 Ctrl+Shift+B 运行错误任务
**A**: 检查 `.vscode/tasks.json`：
- "Build: Parallel-Port-Lookup (g++-11)" 必须是 `isDefault: true`
- "C/C++: g++-11 生成活动文件" 必须是 `isDefault: false`

### Q: 如何用不同的规则文件运行？
**A**: 在命令行传递参数：
```bash
./src/Parallel-Port-Lookup src/ACL_rules/acl_100k.rules
```

---

## 📝 文件大小参考

| 规则文件 | 大小 | 处理时间 |
|---------|------|---------|
| test.rules | 很小 | < 1s |
| acl_10k.rules | ~500KB | 1-2s |
| acl_100k.rules | ~5MB | 5-10s |

---

## ✨ 现在你可以

1. ✅ 编译程序（三种方法任选）
2. ✅ 运行程序（使用任意规则文件）
3. ✅ 调试程序（使用 F5 + GDB）
4. ✅ 查看输出（控制台 + 文件）

**所有功能都已经验证可用！** 🎉
