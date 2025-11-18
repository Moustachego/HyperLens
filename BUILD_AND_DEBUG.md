# 编译和调试说明 — P4lens Parallel-Port-Lookup

## 当前状态 ✅

✓ 编译配置已修复  
✓ Dependent-Set-Prefix-Lookup.cpp 的 main 函数已注释  
✓ VS Code 构建任务已配置为正确链接三个文件  
✓ 程序可以正确运行，生成输出数据  

---

## 如何在 VS Code 中构建和调试

### 方法 1：快速构建 (Ctrl+Shift+B)
按 **`Ctrl+Shift+B`** 或 **`Cmd+Shift+B`** 来构建项目。
- 这会运行 "Build: Parallel-Port-Lookup (g++-11)" 任务
- 该任务会链接所有三个源文件：
  - `src/Parallel-Port-Lookup.cpp`
  - `src/input.cpp`
  - `src/Dependent-Set-Prefix-Lookup.cpp`
- 编译标志：`-std=c++17 -g -DCOMPILE_AS_LIB`
- 输出二进制：`src/Parallel-Port-Lookup`

### 方法 2：启动调试器 (F5)
按 **`F5`** 来启动调试器。
- 会自动执行构建任务（如果尚未构建或有文件更改）
- 使用 GDB 调试器
- 自动将 `src/ACL_rules/test.rules` 作为参数传递给程序
- 执行目录设为 `/home/long/Desktop/P4lens`

---

## 关键配置文件

### `.vscode/tasks.json`
- **"Build: Parallel-Port-Lookup (g++-11)"** — 现在是**默认构建任务**（isDefault: true）
  - 编译所有三个源文件
  - 设置 `-DCOMPILE_AS_LIB` 宏（防止 Dependent-Set-Prefix-Lookup.cpp 中的 main 冲突）
  - 输出到 `src/Parallel-Port-Lookup`

### `.vscode/launch.json`
- **"Launch Parallel-Port-Lookup (build then debug)"** — F5 启动这个配置
  - preLaunchTask: "Build: Parallel-Port-Lookup (g++-11)"
  - program: `${workspaceFolder}/src/Parallel-Port-Lookup`
  - args: `["ACL_rules/test.rules"]` — 自动传递规则文件
  - cwd: `${workspaceFolder}` — 执行目录为项目根目录

---

## 规则文件格式

`src/ACL_rules/test.rules` 应该使用以下格式（制表符分隔）：

```
@SRC_IP1/SRC_MASK	DST_IP1/DST_MASK	SRC_PORT_LO : SRC_PORT_HI	DST_PORT_LO : DST_PORT_HI	PROTO/PROTO_MASK	FLAGS/FLAGS_MASK
```

### 示例：
```
@192.168.1.0/24	10.0.0.0/8	1024 : 65535	80 : 80	6/255	0/0
@192.168.2.0/24	172.16.0.0/12	5000 : 6000	53 : 53	17/255	0/0
@10.0.0.0/16	8.8.8.8/32	1000 : 2000	443 : 443	6/255	0/0
@192.168.0.0/16	0.0.0.0/0	0 : 65535	0 : 65535	1/255	0/0
```

**注意**：字段之间用**制表符**（不是空格）分隔。

---

## 程序输出

程序运行后会生成以下文件在项目根目录：
- `final_ip_table_cidr.txt` — 最终 IP 规则表（CIDR 格式）
- `meta_src_debug.txt` — 调试信息

---

## 可用的规则文件

以下规则文件已在 `src/ACL_rules/` 目录中可用：
- `test.rules` — 小规模测试规则（27 条）
- `test1.rules` — 测试规则 1
- `acl_10k.rules` — 10,000 条 ACL 规则
- `acl_100k.rules` — 100,000 条 ACL 规则
- 其他大规模规则集（fw1_100k、acl1_100k 等）

你可以通过命令行参数运行不同的规则集，例如：
```bash
./src/Parallel-Port-Lookup src/ACL_rules/acl_10k.rules
```

---

## 故障排除

### 问题 1：按 Ctrl+Shift+B 时只编译单个文件
**解决**：确保 `.vscode/tasks.json` 中的 "Build: Parallel-Port-Lookup (g++-11)" 任务的 `isDefault` 设置为 `true`。

### 问题 2：程序输出全是 0
**原因**：通常是因为：
1. 规则文件格式不正确
2. 规则文件未找到
3. 传递的参数有问题

**解决**：
- 使用 F5 调试器时，会自动正确传递 `ACL_rules/test.rules`
- 如果手动运行，确保用正确的相对路径或绝对路径

### 问题 3：编译错误："undefined reference to"
**解决**：确认 `-DCOMPILE_AS_LIB` 宏已设置，这会让 `Dependent-Set-Prefix-Lookup.cpp` 的 main 函数被禁用。

---

## 常用工作流程

1. **开发代码** → 在编辑器中修改文件
2. **按 Ctrl+Shift+B** → 快速构建
3. **按 F5** → 启动调试器（会自动重新构建）
4. **查看输出** → 在 VS Code 终端或输出文件中查看结果

---

**所有配置现已完成，你可以开始使用 VS Code 的图形界面进行构建和调试！**
