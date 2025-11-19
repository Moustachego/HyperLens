#pragma once  // 或者下面这种传统写法
#include <vector>
#include <cstdint>

using namespace std;

// 占位输出结构
struct SRC_SRAM_Table {
    uint16_t GroupID1;
    uint16_t SP_Quotient;
    vector<size_t> bitmap; // 对应哪些 merged_ip_table 条目
    uint16_t GroupID2;
};

struct SRC_TCAM_Table {
    uint16_t GroupID1;
    uint16_t Src_Port_TCAM;
    uint16_t GroupID2;
};

struct BlockInfo {
    uint16_t block_idx;
    uint32_t bitmap;
};

// 全局 block 元数据，记录属于哪些规则以及是否已分配到 TCAM
struct BlockMeta {
    uint16_t block_idx;
    uint32_t bitmap;              // 端口位图
    std::vector<size_t> owners;   // 哪些规则（或 merged_ip_table index）包含这个 block
    bool assigned = false;        // 是否已经被分配给 TCAM（被合并成 superblock）
};
