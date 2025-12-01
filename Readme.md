# HyperLens

高性能可编程交换机包分类工具链，基于三阶段依赖查找架构，实现 99.9% 的内存优化。

## 项目简介

HyperLens 是一个针对可编程交换机的 ACL 规则优化工具，通过创新的**依赖查找策略**将传统的笛卡尔积查找转换为三阶段流水线：

```
[数据包] → [阶段1: IP+协议] → GID1 → [阶段2: 源端口] → GID2 → [阶段3: 目的端口] → 动作
```

**核心优势：**
- 内存占用减少 100-1000 倍（测试：505K 条目 → 1.4K 条目）
- 保持线速查找性能
- 支持 Intel Tofino 等 P4 可编程交换机

## 快速开始

### 环境要求

- `g++-11` 或更高版本（支持 C++17）
- （可选）Intel SDE + conda 环境用于硬件集成

### 编译运行

```bash
# 一键编译并运行示例
./build_and_run.sh

# 使用自定义规则集
./src/HyperLens src/ACL_rules/your_rules.rules
```

### 输入格式

规则文件格式（五元组 ACL）：
```
@<源IP/前缀> <目的IP/前缀> <源端口范围> <目的端口范围> <协议/掩码> <动作/掩码>
```

示例：
```
@10.1.0.0/16 20.0.0.0/8 1000:2000 3000:4000 0x06/0xFF 0x0000/0x0000
```

### 输出文件

生成的表文件位于 `src/output/`：

- `final_ip_table_cidr.txt` - 阶段1 IP 表（含 GID1 分配）
- `SRC_TCAM_Table.txt` / `SRC_SRAM_Table.txt` - 阶段2 源端口表
- `DST_TCAM_Table.txt` / `DST_SRAM_Table.txt` - 阶段3 目的端口表（含最终动作）
- `meta_merged.txt` - GID 到端口范围的元数据映射

## 项目结构

```
HyperLens/
├── P4/tofino2.p4                        # P4 数据平面程序
├── src/
│   ├── HyperLens.cpp                    # 主程序入口
│   ├── Loader.cpp                       # 规则解析
│   ├── Dependent-Set-Prefix-Lookup.cpp # IP 合并与交集单元检测
│   ├── Parallel-Port-Lookup.cpp        # 端口表生成（TCAM/SRAM）
│   └── ACL_rules/                       # 测试规则集
├── Test.py                              # 控制平面加载程序
├── build.sh / install.sh                # P4 编译脚本
└── build_and_run.sh                     # 一键编译运行脚本
```

## 工作原理

1. **规则解析**：加载五元组 ACL 规则
2. **IP 表合并**：合并相同 IP 范围的规则，检测交集边界
3. **CIDR 转换**：将 IP 范围转换为 CIDR 前缀列表
4. **端口表生成**：分块处理端口范围，生成 TCAM/SRAM 表项
5. **表导出**：输出硬件就绪的查找表

详细算法说明请参考 `.github/copilot-instructions.md`

## P4 硬件集成

需要 Intel SDE 环境：

```bash
# 设置环境变量
export SDE=/opt/bf-sde
export SDE_INSTALL=/opt/bf-sde-install

# 编译 P4 程序
./build.sh
./install.sh

# 加载表到交换机
conda activate controller
./run_controller.sh
```

## 性能数据

基于 ClassBench 数据集测试（10 万条规则，70% 重叠）：

| 指标 | 传统方法 | HyperLens | 改进 |
|------|---------|-----------|------|
| IP 表条目 | 505,186 | 1,412 | **357× ↓** |
| TCAM 占用 | ~2M | ~5K | **400× ↓** |
| 内存占用 | ~50 MB | ~150 KB | **99.7% ↓** |

## 作者信息

**作者：** Wei Juzhong (weijzh)  
**邮箱：** weijzh@pcl.ac.cn  
**机构：** Peng Cheng Laboratory  
**版本：** 1.0  
**更新日期：** 2025-12-01

## 引用

如果在学术研究中使用本项目，请引用：

```bibtex
@inproceedings{HyperLens2025,
  title={HyperLens: Scalable High-Speed Packet Classification on Programmable Switches},
  author={Wei, Juzhong and others},
  booktitle={Proceedings of [Conference Name]},
  year={2025}
}
```

---

**详细文档：** 参见 `.github/copilot-instructions.md` 获取完整的开发指南和架构说明。

