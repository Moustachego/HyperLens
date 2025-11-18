#!/bin/bash
# 完整的编译和运行脚本
# 用途：一键编译和运行 Parallel-Port-Lookup 程序

set -e  # 任何错误就停止

PROJECT_ROOT="/home/long/Desktop/P4lens"
cd "$PROJECT_ROOT"

echo "================================"
echo "P4lens Parallel-Port-Lookup 构建"
echo "================================"
echo ""

# 1. 清理旧的二进制文件
echo "[1/4] 清理旧的二进制文件..."
rm -f src/Parallel-Port-Lookup
echo "✓ 清理完成"
echo ""

# 2. 编译
echo "[2/4] 编译 (g++-11 -std=c++17)..."
/usr/bin/g++-11 -std=c++17 -fdiagnostics-color=always -g -DCOMPILE_AS_LIB \
    src/Parallel-Port-Lookup.cpp \
    src/input.cpp \
    src/Dependent-Set-Prefix-Lookup.cpp \
    -o src/Parallel-Port-Lookup 2>&1
echo "✓ 编译成功"
echo ""

# 3. 验证二进制文件存在
echo "[3/4] 验证二进制文件..."
if [ -f src/Parallel-Port-Lookup ]; then
    ls -lh src/Parallel-Port-Lookup
    echo "✓ 二进制文件已生成"
else
    echo "✗ 错误：二进制文件未生成！"
    exit 1
fi
echo ""

# 4. 运行程序
echo "[4/4] 运行程序..."
echo "======== 程序输出 ========"
./src/Parallel-Port-Lookup src/ACL_rules/test.rules
echo "======== 程序完成 ========"
echo ""

# 5. 检查输出文件
echo "[5/4] 检查生成的输出文件..."
if [ -f final_ip_table_cidr.txt ]; then
    echo "✓ final_ip_table_cidr.txt ($(wc -l < final_ip_table_cidr.txt) 行)"
fi
if [ -f meta_src_debug.txt ]; then
    echo "✓ meta_src_debug.txt ($(wc -l < meta_src_debug.txt) 行)"
fi
echo ""
echo "================================"
echo "✓ 所有步骤完成！"
echo "================================"
