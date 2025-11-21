#pragma once  // 或者下面这种传统写法
#include <vector>
#include <cstdint>
#include <bitset>
#include <string>

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
    uint16_t src_port_value;   // 基准端口值
    uint16_t src_port_mask;   // 16-bit mask: 1=固定，0=通配
    uint16_t GroupID2;
    std::string bin_prefix;
};

struct PortRangeEntry {
    uint32_t group_id;               // GroupIDs
    uint32_t src_lo;                 // Src_lo
    uint32_t src_hi;                 // Src_hi
    vector<uint32_t> idx_list;       // 你的 {0},{1}... 用这个表示
    vector<uint32_t> initnum_list;   // InitNum_list
};

// 全局 block 元数据，记录属于哪些规则以及是否已分配到 TCAM
struct BlockMeta {
    uint32_t group_id;
    uint16_t block_idx;
    uint32_t SP;
    uint32_t start;       // 新增：block 实际起始端口
    uint32_t end;         // 新增：block 实际结束端口 
    std::string bin_prefix;
    bool can_use_prefix;
    std::bitset<32> bitmap; 
    bool assigned = false;        // 是否已经被分配给 TCAM（被合并成 superblock）
    bool single_value = false;    // 新增：是否为单个端口值
};

// 占位输出结构
struct Mate_SRC_LIST {
    std::vector<int> group_ids;      // GID 列表（你目前只有 1 个 GID）
    uint32_t src_lo;
    uint32_t src_hi;
    std::vector<int> idx_list;       // 合并后的多个 Idx（重排后 i+1）
    std::vector<int> initnum_list;   // 合并后的多个 InitNum
};

// 占位输出结构
struct Mate_DST_LIST {
    std::vector<int> group_ids;      // GID 列表（你目前只有 1 个 GID）
    uint32_t dst_lo;
    uint32_t dst_hi;
    std::vector<int> idx_list;       // 合并后的多个 Idx（重排后 i+1）
    std::vector<int> initnum_list;   // 合并后的多个 InitNum
};
