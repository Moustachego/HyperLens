#pragma once  // 或者下面这种传统写法
#include <vector>
#include <cstdint>
#include <bitset>
#include <string>
#include "Loader.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"

using namespace std;

// 端口类型枚举（需要在结构体之前定义）
enum class DST_Port_Type {
    POINT = 0,      // 点（单个点值）
    SHORT_RANGE = 1, // 短区间
    LONG_RANGE = 2,  // 长区间（1025-65535、5001-65535）
    WILDCARD = 3     // 全通配符（0-65535）
};

struct PortRangeEntry {
    uint32_t group_id;               // GroupIDs
    uint32_t src_lo;                 // Src_lo
    uint32_t src_hi;                 // Src_hi
    vector<uint32_t> idx_list;       // 你的 {0},{1}... 用这个表示
    vector<uint32_t> initnum_list;   // InitNum_list
};

// 全局 block 元数据，记录属于哪些规则以及是否已分配到 TCAM
struct BlockMeta_SRC {
    uint32_t group_id;
    uint32_t group_id2;
    uint16_t block_idx;
    uint32_t SP;
    uint32_t start;       // 新增：block 实际起始端口
    uint32_t end;         // 新增：block 实际结束端口 
    uint32_t src_item_idx; // 新增：来源于哪个 src_items 的索引
    std::string bin_prefix;
    bool can_use_prefix;
    std::bitset<32> bitmap; 
    bool assigned = false;        // 是否已经被分配给 TCAM（被合并成 superblock）
    bool single_value = false;    // 新增：是否为单个端口值
};

// 全局 block 元数据，记录属于哪些规则以及是否已分配到 TCAM
struct BlockMeta_DST {
    uint32_t group_id;
    uint32_t group_id2;
    std::vector<int> Action;
    std::string action;            // 原始的 action 字符串格式，如 "0x0000/0x0200"
    uint16_t block_idx;
    uint32_t SP;
    uint32_t start;       // 新增：block 实际起始端口
    uint32_t end;         // 新增：block 实际结束端口 
    uint32_t src_item_idx; // 新增：来源于哪个 src_items 的索引
    std::string bin_prefix;
    bool can_use_prefix;
    std::bitset<32> bitmap; 
    bool assigned = false;        // 是否已经被分配给 TCAM（被合并成 superblock）
    bool single_value = false;    // 新增：是否为单个端口值
    DST_Port_Type port_type = DST_Port_Type::SHORT_RANGE; // 端口类型标记（从 DST_Port_Item 继承）
};

// 为兼容现有代码，默认的 BlockMeta 映射到 SRC 版本。
// 新的 DST 流程应当使用 BlockMeta_DST 明确区分。
using BlockMeta = BlockMeta_SRC;

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
    std::string action;               // 来自规则的 action 字段，保存完整格式如 "0x0000/0x0200"
};

// 用于给 SRC 表分配第二个 GID 的临时结构
struct SRC_Port_Item{
    std::vector<int> group_ids1;      // 原始 GID 列表
    uint32_t src_lo;
    uint32_t src_hi;
    std::vector<int> group_ids2;      // 分配后的 GID2（顺序分配）
};



// 对称的 DST 项结构
struct DST_Port_Item{
    std::vector<int> group_ids1;      // 原始 GID 列表
    std::vector<int> group_ids2;      // GID2 列表
    uint32_t dst_lo;
    uint32_t dst_hi;
    std::vector<int> Action;      // 分配后的 GID2（顺序分配或 action id）
    std::string action;            // 原始的 action 字符串格式，如 "0x0000/0x0200"
    DST_Port_Type port_type = DST_Port_Type::SHORT_RANGE; // 端口类型标记
};

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

// 占位输出结构
struct DST_SRAM_Table {
    uint16_t GroupID2;
    uint16_t SP_Quotient;
    vector<size_t> bitmap; // 对应哪些 merged_ip_table 条目
    std::string Action;    // 原始的 action 字符串格式，如 "0x0000/0x0200"
};

struct DST_TCAM_Table {
    uint16_t GroupID2;
    uint16_t dst_port_value;   // 基准端口值
    uint16_t dst_port_mask;   // 16-bit mask: 1=固定，0=通配
    std::string Action;        // 原始的 action 字符串格式，如 "0x0000/0x0200"
    std::string bin_prefix;
    DST_Port_Type port_type = DST_Port_Type::SHORT_RANGE; // 端口类型标记
};

struct RmaxEntity {
    uint32_t src_lo, src_hi;
    uint32_t dst_lo, dst_hi;
    uint8_t  proto;
    size_t   rmax_id;
};


// ===== Function Declarations =====

void load_and_create_IP_table(
    vector<IPRule>& ip_table,
    vector<PortRule>& port_table,
    vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& mateinfo
);

void create_Table_for_port(
    const std::vector<PortRule>& port_table,
    const std::vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& mateinfo
);


