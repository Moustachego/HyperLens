#include <vector>
using namespace std;


struct IntersectionCell {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;   
    std::vector<size_t> rule_indices; // 记录由哪些规则覆盖（索引为 merged_ip_table 索引）
};

struct FinalIPRule {
    uint32_t src_lo;
    uint32_t src_hi;
    uint32_t dst_lo;
    uint32_t dst_hi;
    uint8_t  proto;
    uint32_t priority;              // 可以设置为0或原始优先级
    vector<int> group_ids;          // 自身ID + Rmax的Group_ID
    bool is_cell = false;   // 是否为 intersection cell 产生的规则
    bool is_rmax = false;   // 是否属于 Rmax 区域
    std::vector<size_t> merged_R;
};