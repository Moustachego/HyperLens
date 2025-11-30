#!/bin/bash
# 完整的编译和运行脚本
# 用途：一键编译和运行 P4Lens 程序

set -e  # 任何错误就停止

PROJECT_ROOT="/home/long/Desktop/P4lens"
cd "$PROJECT_ROOT"

echo "=============================================================================="
echo "HyperLens — Scalable High-Speed Packet Classification on Programmable Switches"
echo "=============================================================================="
echo ""

# 1. 清理旧的二进制文件
echo "[1/5] 清理旧的二进制文件..."
rm -f src/P4Lens
echo "✓ 清理完成"
echo ""

# 2. 编译
echo "[2/5] 编译 (g++-11 -std=c++17)..."
/usr/bin/g++-11 -std=c++17 -fdiagnostics-color=always -g \
    src/P4Lens.cpp \
    src/Parallel-Port-Lookup.cpp \
    src/Loader.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/P4Lens 2>&1
echo "✓ 编译成功"
echo ""

# 3. 验证二进制文件存在
echo "[3/5] 验证二进制文件..."
if [ -f src/P4Lens ]; then
    ls -lh src/P4Lens
    echo "✓ 二进制文件已生成"
else
    echo "✗ 错误：二进制文件未生成！"
    exit 1
fi
echo ""

# 4. 运行程序 (修改输入规则)
echo "[4/5] 运行程序..."
echo "================================= 程序输出 ===================================="
./src/P4Lens src/ACL_rules/acl_100k.rules
echo "================================= 程序完成 ===================================="
echo ""

# 5. 检查输出文件
echo "[5/5] 检查生成的输出文件..."
if [ -f final_ip_table_cidr.txt ]; then
    echo "✓ final_ip_table_cidr.txt ($(wc -l < final_ip_table_cidr.txt) 行)"
fi
if [ -f meta_merged.txt ]; then
    echo "✓ meta_merged.txt ($(wc -l < meta_merged.txt) 行)"
fi
if [ -f SRC_TCAM_Table.txt ]; then
    echo "✓ SRC_TCAM_Table.txt ($(wc -l < SRC_TCAM_Table.txt) 行)"
fi
if [ -f SRC_SRAM_Table.txt ]; then
    echo "✓ SRC_SRAM_Table.txt ($(wc -l < SRC_SRAM_Table.txt) 行)"
fi
if [ -f DST_TCAM_Table.txt ]; then
    echo "✓ DST_TCAM_Table.txt ($(wc -l < DST_TCAM_Table.txt) 行)"
fi
if [ -f DST_SRAM_Table.txt ]; then
    echo "✓ DST_SRAM_Table.txt ($(wc -l < DST_SRAM_Table.txt) 行)"
fi
echo ""
echo "=============================================================================="
echo "                               ✓ 所有步骤完成！"
echo "=============================================================================="