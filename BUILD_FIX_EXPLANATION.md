# VS Code 编译配置说明 - Parallel-Port-Lookup

## 🔧 刚才发生了什么？

你遇到的错误是因为 **Ctrl+Shift+B** 运行了错误的编译任务，导致只编译单个文件而没有链接必需的其他 .cpp 文件。

### 错误症状：
```
undefined reference to `merge_same_ip_entry(...)`
undefined reference to `find_Rmax_for_merged_ip_table(...)`
undefined reference to `load_rules_from_file(...)`
... 等等
```

### 根本原因：
VS Code 的默认任务是 "C/C++: g++-11 生成活动文件"，它只编译当前活动文件 (`${file}`)，不链接其他必需的源文件。

---

## ✅ 我的修复方案

### 修改 `.vscode/tasks.json`：
1. **设置正确的默认任务**
   - 将 **"Build: Parallel-Port-Lookup (g++-11)"** 的 `isDefault` 改为 `true`
   - 将 **"C/C++: g++-11 生成活动文件"** 的 `isDefault` 改为 `false`

2. **正确的任务配置**
   - "Build: Parallel-Port-Lookup (g++-11)" 链接三个源文件：
     - `src/Parallel-Port-Lookup.cpp`
     - `src/input.cpp`
     - `src/Dependent-Set-Prefix-Lookup.cpp`
   - 使用编译标志：`-std=c++17 -g -DCOMPILE_AS_LIB`

---

## 🚀 现在如何正确使用

### ✔️ 正确的编译方式（推荐）

**按 `Ctrl+Shift+B`**
- 会自动运行 "Build: Parallel-Port-Lookup (g++-11)" 任务
- 链接所有必需的 .cpp 文件
- 输出：`src/Parallel-Port-Lookup` 可执行文件

**按 `F5`**
- 自动执行上面的编译任务
- 启动 GDB 调试器
- 自动运行程序并传递 `src/ACL_rules/test.rules` 参数

### ❌ 避免这些方式

**不要使用** "C/C++: g++-11 生成活动文件" 任务，因为它：
- 只编译当前活动文件
- 不链接其他必需的 .cpp 文件
- 导致链接错误

---

## 📝 编译命令详解

### 完整的编译命令（三个文件一起链接）：
```bash
/usr/bin/g++-11 \
  -std=c++17 \
  -fdiagnostics-color=always \
  -g \
  -DCOMPILE_AS_LIB \
  src/Parallel-Port-Lookup.cpp \
  src/input.cpp \
  src/Dependent-Set-Prefix-Lookup.cpp \
  -o src/Parallel-Port-Lookup
```

**关键点**：
- `-DCOMPILE_AS_LIB` — 禁用 Dependent-Set-Prefix-Lookup.cpp 中的 main() 函数
- 三个 .cpp 文件都必须包含在编译命令中
- 输出到 `src/Parallel-Port-Lookup`

---

## 🎯 验证编译成功的标志

编译完成后应该看到：
```
✓ 编译成功
[Parallel-Port-Lookup] Loaded 27 rules from 'src/ACL_rules/test.rules'
[split_rules] IP table size = 27, Port table size = 27
[merge_same_ip_entry] Original IP rules = 27, merged = 21
...
```

---

## 📂 项目文件结构

```
src/
├── Parallel-Port-Lookup.cpp       ← 主程序（含 main()）
├── Parallel-Port-Lookup.hpp       ← 数据结构定义
├── input.cpp                      ← 规则加载函数
├── input.hpp                      ← 规则加载函数声明
├── Dependent-Set-Prefix-Lookup.cpp    ← IP 处理函数（main 被注释）
├── Dependent-Set-Prefix-Lookup.hpp    ← IP 处理函数声明
├── Parallel-Port-Lookup           ← 编译后的可执行文件
└── ACL_rules/
    ├── test.rules                 ← 小规模测试规则
    ├── test1.rules
    ├── acl_10k.rules              ← 10,000 条规则
    ├── acl_100k.rules             ← 100,000 条规则
    └── ...其他规则文件
```

---

## 💡 快速参考

| 操作 | 快捷键 | 说明 |
|------|--------|------|
| **编译** | `Ctrl+Shift+B` | 使用默认任务编译（链接所有 .cpp） |
| **调试运行** | `F5` | 自动编译并启动调试器 |
| **构建输出** | — | `src/Parallel-Port-Lookup` |
| **规则文件** | — | `src/ACL_rules/test.rules` 等 |

---

## 🔍 如果还有问题

1. **确保 `.vscode/tasks.json` 中 "Build: Parallel-Port-Lookup (g++-11)" 的 `isDefault: true`**
2. **确保有三个 .cpp 文件都在项目中**
3. **确保规则文件存在在 `src/ACL_rules/` 目录下**

**现在一切都应该工作正常了！** 🎉
