#pragma once
/** *************************************************************/
// GID2 Encoding Optimizer — Header
//
// Declares run_gid2_optimizer() for integration into HyperLens pipeline.
// Can also be compiled standalone (GID2_Optimizer.cpp has its own main).
// @Author: weijzh (weijzh@pcl.ac.cn)
/************************************************************* */

#include <string>

// 读取 DST_TCAM_Table，按 (DstPort, Action) 分组后用 Trie 压缩 GID2 编码，
// 输出优化后的 DST_TCAM_Table_Optimized.txt
// 返回值: 优化后的条目数（0 表示失败）
size_t run_gid2_optimizer(
    const std::string& input_file  = "src/output/DST_TCAM_Table.txt",
    const std::string& output_file = "src/output/DST_TCAM_Table_Optimized.txt"
);
