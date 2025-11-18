# P4lens - Parallel Port Lookup Tool

## 快速开始

### 最简单的方式（推荐）
```bash
bash build_and_run.sh
```

### VS Code 方式
- 编译：`Ctrl+Shift+B`
- 调试运行：`F5`

### 手动编译运行
```bash
/usr/bin/g++-11 -std=c++17 -g -DCOMPILE_AS_LIB \
    src/Parallel-Port-Lookup.cpp src/input.cpp src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/Parallel-Port-Lookup

./src/Parallel-Port-Lookup src/ACL_rules/test.rules
```

## 文档

- **COMPLETE_GUIDE.md** - 完整使用指南和常见问题
- **BUILD_AND_DEBUG.md** - 构建和调试说明
- **BUILD_FIX_EXPLANATION.md** - 编译问题修复说明
- **.github/copilot-instructions.md** - AI 助手指令

## 可用的规则文件

- `src/ACL_rules/test.rules` - 27 条规则（快速测试）
- `src/ACL_rules/acl_10k.rules` - 10,000 条规则
- `src/ACL_rules/acl_100k.rules` - 100,000 条规则
- 更多规则文件见 `src/ACL_rules/` 目录

## 输出文件

程序运行后会生成：
- `final_ip_table_cidr.txt` - 最终 IP 规则表
- `meta_src_debug.txt` - 调试信息

## 编译依赖

- g++-11
- C++17 标准

## 项目结构

```
src/
├── Parallel-Port-Lookup.cpp    # 主程序
├── input.cpp                   # 规则加载
├── Dependent-Set-Prefix-Lookup.cpp  # IP 处理
├── *.hpp                       # 头文件
└── ACL_rules/                  # 规则文件目录

.vscode/                         # VS Code 配置
build_and_run.sh                # 自动编译脚本
```

---

**✅ 所有编译和运行问题已解决！** 

详见 `COMPLETE_GUIDE.md` 获取完整的文档和 FAQ。
