/** *************************************************************/
// @Name: Parallel Port Lookup.cpp
// @Function: Handle parallel port lookup for IP rules
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-10-30
/************************************************************* */

#include <iostream>
#include <vector>
#include <map>
#include <tuple>
#include <set>
#include <algorithm>
#include <fstream>
#include <unordered_map>
#include <limits>
#include <unordered_set>
#include <sstream>
#include <string>
#include <cstdint>
#include <cmath>
#include <iomanip> 
#include <bitset>
#include "Loader.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"
#include "Parallel-Port-Lookup.hpp"

using namespace std;


static const size_t MAX_BLOCKS_ALLOWED = 1000000000;    // 总 blocks 上限（防止 OOM），可调 这有什么作用？
static const uint32_t MAX_SINGLE_RANGE = 1u << 20;

// 判断是否是长范围区间（用于降低优先级）
// 如果 DST 范围长度 > 10000，认为是长范围
inline bool is_long_range_dst(int dst_lo, int dst_hi) {
    // 排除完全通配符 0-65535
    if (dst_lo == 0 && dst_hi == 65535) {
        return false;
    }
    // 如果范围长度 > 10000，认为是长范围
    return (dst_hi - dst_lo + 1) > 10000;
} 


std::bitset<32> generate_32bit_bitmap(uint32_t block_base, uint32_t L, uint32_t H)
{
    std::bitset<32> bitmap; // 默认全部 0
    // block_base 是 SP*32（对齐的 32-port block 起始端口）
    // 计算在 block 中真正要设置 1 的区间（相对 block_base 的偏移）
    uint32_t s = std::max<uint32_t>(block_base, L);
    uint32_t e = std::min<uint32_t>(block_base + 31u, H);
    if (s <= e) {
        for (uint32_t p = s; p <= e; ++p) {
            // 反转位序：高端口对应低位（右侧），低端口对应高位（左侧）
            // 原本 port p 对应 bit[p-block_base]，现在改为 bit[31-(p-block_base)]
            uint32_t bit_idx = 31u - (p - block_base);
            bitmap.set(bit_idx);
        }
    }
    // 未命中的位保持 0（bitset 初始化为 0）
    return bitmap;
}

// 把 bitset<32> 转成可读字符串：
// lsb_on_right = true -> 最右边是 bit0（block_start），与你之前展示的 "000...01111" 风格一致
// lsb_on_right = false -> 最左边是 bit31（常见二进制从 MSB->LSB）
// 返回 32 字符长的 "0"/"1" 字符串
std::string bitmap32_to_string(const std::bitset<32> &bm, bool lsb_on_right = true)
{
    std::string s;
    s.reserve(32);
    if (lsb_on_right) {
        // 为兼容以前展示风格，这里把 bit0 (offset 0) 放在字符串左侧
        // 即按 bit0..bit31 的顺序输出，使得左侧对应 block 内的低偏移
        for (int i = 0; i < 32; ++i) s.push_back(bm.test(i) ? '1' : '0');
    } else {
        // MSB on left (bit31 leftmost) == same as above but make alternative for clarity
        for (int i = 31; i >= 0; --i) s.push_back(bm.test(i) ? '1' : '0');
        // (实际上上面两种在实现上相同；保留这一参数以便将来反转显示，如果需要可以改)
    }
    return s;
}

std::string compute_bin_prefix(uint32_t start, uint32_t end)
{
    // 找到 start 和 end 二进制表示的公共前缀
    std::string prefix;
    for (int i = 15; i >= 0; --i) { // 16-bit 端口
        bool bstart = (start >> i) & 1;
        bool bend   = (end   >> i) & 1;
        if (bstart == bend)
            prefix += bstart ? '1' : '0';
        else {
            prefix += std::string(i + 1, '*'); // 剩余位都用 *
            break;
        }
    }
    return prefix;
}

inline bool is_power_of_two(uint32_t n) {
    return n && ((n & (n - 1)) == 0);
}


struct SplitResult {
    vector<BlockMeta> blocks;              // 拆分后的 block
    vector<SRC_Port_Item> full_range_items_src;   // 0-65535 范围的 item (now SRC_Port_Item)
};

// DST 专用拆分结果
struct SplitResult_DST {
    std::vector<BlockMeta_DST> blocks;              // 拆分后的 block（DST 特定）
    std::vector<DST_Port_Item> full_range_items_dst; // 全端口项
};


SplitResult split_port_range_into_blocks_for_src(const vector<SRC_Port_Item> &meta_src)
{
    SplitResult result;
    size_t total_blocks = 0;

    for (size_t item_idx = 0; item_idx < meta_src.size(); ++item_idx) {
        const auto &item = meta_src[item_idx];
        if (item.group_ids1.empty()) continue;

        uint32_t L = item.src_lo;
        uint32_t H = item.src_hi;
        if (L > H) continue;

        uint64_t range_len = (uint64_t)H - (uint64_t)L + 1u;
        if (range_len > MAX_SINGLE_RANGE) continue;

        uint32_t group_id = item.group_ids1[0];
        uint32_t group_id2 = item.group_ids2.empty() ? 0 : static_cast<uint32_t>(item.group_ids2[0]);

        // -------- 特殊处理：全端口 0-65535 --------
        if (L == 0 && H == 65535) {
            result.full_range_items_src.push_back(item); // 保存全端口 item (SRC_Port_Item)
            continue;  // 跳过拆分
        }

        // 从 L 到 H 拆分 block
        uint32_t start = L;
        uint32_t block_idx = 0;

        while (start <= H) {
            uint32_t SP = start / 32;
            uint32_t block_start = start;          // 第一个 block 用 start
            uint32_t block_end;
            
            if (start != L) {                       // 后续 block 可以对齐到 32 的倍数
                block_start = SP * 32;
            }

            // 第一个 block: 从 start 到下一个 32 的倍数 -1，或者 H
            if (start % 32 != 0) {
                block_end = min(H, (start / 32 + 1) * 32 - 1);
            } else {
                // 对齐 32 的倍数 block
                block_end = min(H, start + 31);
            }
            BlockMeta bm;
            bm.group_id = group_id;
            bm.src_item_idx = static_cast<uint32_t>(item_idx);
            bm.group_id2 = group_id2;
            bm.block_idx = block_idx;
            bm.SP = SP;
            bm.start = block_start;   // 记录真实起始端口
            bm.end   = block_end;     // 记录真实结束端口
            bm.assigned = false;
            bm.single_value = (block_start == block_end);

            // -------- 判断是否可以用单一 prefix --------
            uint32_t block_len = block_end - block_start + 1;
            bool can_use_prefix = is_power_of_two(block_len) && (block_start % block_len == 0);

            if (can_use_prefix) {
                bm.can_use_prefix = true;
                bm.bin_prefix = compute_bin_prefix(block_start, block_end);
            } else {
                bm.can_use_prefix = false;
                // 使用 SP*32 作为 bitmap 的基准，使得 bitmap 的位序与 SP_Quotient 对齐
                uint32_t block_base = SP * 32;
                bm.bitmap = generate_32bit_bitmap(block_base, block_start, block_end);
            }

            result.blocks.push_back(move(bm));
            total_blocks++;
            if (total_blocks > MAX_BLOCKS_ALLOWED) {
                cerr << "[FATAL] total blocks exceed MAX_BLOCKS_ALLOWED.\n";
                abort();
            }

            block_idx++;
            start = block_end + 1;
        }
    }

    // debug prints removed

    return result;
}


// DST 侧的拆分函数：把 0-65535 单独收集到 full_range_items_dst，其余拆分为 BlockMeta_DST
SplitResult_DST split_port_range_into_blocks_for_dst(const std::vector<DST_Port_Item> &meta_dst)
{
    SplitResult_DST result;
    size_t total_blocks = 0;
    // 长区间计数已移除（不再输出调试信息）

    for (size_t item_idx = 0; item_idx < meta_dst.size(); ++item_idx) {
        const auto &item = meta_dst[item_idx];
        if (item.group_ids1.empty()) continue;

        uint32_t L = item.dst_lo;
        uint32_t H = item.dst_hi;
        if (L > H) continue;

        uint64_t range_len = (uint64_t)H - (uint64_t)L + 1u;
        if (range_len > MAX_SINGLE_RANGE) continue;

        uint32_t group_id = item.group_ids1[0];
        uint32_t group_id2 = item.group_ids2.empty() ? 0 : static_cast<uint32_t>(item.group_ids2[0]);
        
        // 不输出调试信息

        // 全端口特殊处理
        if (L == 0 && H == 65535) {
            result.full_range_items_dst.push_back(item);
            continue;
        }

        uint32_t start = L;
        uint32_t block_idx = 0;
        while (start <= H) {
            uint32_t SP = start / 32;
            uint32_t block_start = start;
            uint32_t block_end;

            if (start != L) block_start = SP * 32;

            if (start % 32 != 0) {
                block_end = std::min(H, (start / 32 + 1) * 32 - 1);
            } else {
                block_end = std::min(H, start + 31);
            }

            BlockMeta_DST bm;
            bm.group_id = group_id;
            bm.group_id2 = group_id2;
            bm.Action = item.Action; // preserve Action list from DST item
            bm.action = item.action; // 保存原始的 action 字符串格式
            bm.src_item_idx = static_cast<uint32_t>(item_idx);
            bm.block_idx = block_idx;
            bm.SP = SP;
            bm.start = block_start;
            bm.end = block_end;
            bm.assigned = false;
            bm.single_value = (block_start == block_end);
            bm.port_type = item.port_type; // 继承端口类型
            
            // 继承端口类型（不做调试计数）

            uint32_t block_len = block_end - block_start + 1;
            bool can_use_prefix = is_power_of_two(block_len) && (block_start % block_len == 0);

            if (can_use_prefix) {
                bm.can_use_prefix = true;
                bm.bin_prefix = compute_bin_prefix(block_start, block_end);
            } else {
                bm.can_use_prefix = false;
                uint32_t block_base = SP * 32;
                bm.bitmap = generate_32bit_bitmap(block_base, block_start, block_end);
            }

            result.blocks.push_back(std::move(bm));
            total_blocks++;
            if (total_blocks > MAX_BLOCKS_ALLOWED) {
                cerr << "[FATAL] total DST blocks exceed MAX_BLOCKS_ALLOWED.\n";
                abort();
            }

            block_idx++;
            start = block_end + 1;
        }
    }

    // 已完成拆分（调试输出已移除）

    return result;
}


// Overload: convert from vector<Mate_SRC_LIST> to vector<MergedItem>
vector<MergedItem> convert_mateifno_to_vector(
    const std::vector<Mate_SRC_LIST> &mate_src_list)
{
    vector<MergedItem> result;
    result.reserve(mate_src_list.size());
    for (const auto &s : mate_src_list) {
        MergedItem mi;
        mi.group_ids = s.group_ids;
        mi.src_lo = s.src_lo;
        mi.src_hi = s.src_hi;
        mi.idx_list = s.idx_list;
        mi.initnum_list = s.initnum_list;
        result.push_back(std::move(mi));
    }
    return result;
}

// Overload: convert from vector<Mate_DST_LIST> to vector<MergedItem>
vector<MergedItem> convert_mateifno_to_vector(
    const std::vector<Mate_DST_LIST> &mate_dst_list)
{
    vector<MergedItem> result;
    result.reserve(mate_dst_list.size());
    for (const auto &d : mate_dst_list) {
        MergedItem mi;
        mi.group_ids = d.group_ids;
        mi.dst_lo = d.dst_lo;
        mi.dst_hi = d.dst_hi;
        mi.idx_list = d.idx_list;
        mi.initnum_list = d.initnum_list;
        mi.action = d.action;  // 传递 action 字段
        result.push_back(std::move(mi));
    }
    return result;
}

void fill_full_range_items_to_src_tcam(
    const std::vector<SRC_Port_Item>& full_range_items,
    std::vector<SRC_TCAM_Table>& src_tcam_table)
{
    for (const auto& item : full_range_items)
    {
        if (item.group_ids1.empty()) {
            std::cerr << "[WARN] SRC_Port_Item has empty group_ids1, skipping.\n";
            continue;
        }

        // 假设全端口范围 0-65535
        if (item.src_lo == 0 && item.src_hi == 65535)
        {
            SRC_TCAM_Table entry;
            entry.GroupID1 = static_cast<uint16_t>(item.group_ids1[0]);
            entry.src_port_value = 0;    // 基准端口
            entry.src_port_mask  = 0x0000; // 全端口通配
            entry.bin_prefix = std::string(16, '*');
            entry.GroupID2 = item.group_ids2.empty() ? entry.GroupID1 : static_cast<uint16_t>(item.group_ids2[0]);

            src_tcam_table.push_back(std::move(entry));
        }
        else
        {
            std::cerr << "[INFO] SRC_Port_Item is not full range, skipping: "
                      << item.src_lo << "-" << item.src_hi << "\n";
        }
    }

    std::cerr << "[INFO] fill_full_range_items_to_src_tcam produced "
              << src_tcam_table.size() << " entries.\n";
}

// 对 DST 全端口项进行 TCAM 填充：以 G-ID2 为主键、Action 为最终动作，中间端口字段为通配符
void fill_full_range_items_to_dst_tcam(
    const std::vector<DST_Port_Item>& full_range_items,
    std::vector<DST_TCAM_Table>& dst_tcam_table)
{
    for (const auto &item : full_range_items) {
        if (item.group_ids1.empty()) {
            std::cerr << "[WARN] DST_Port_Item has empty group_ids1, skipping.\n";
            continue;
        }

        if (item.dst_lo == 0 && item.dst_hi == 65535) {
            DST_TCAM_Table entry{};
            // 不处理 G-ID1；以 G-ID2 为索引起点
            entry.GroupID2 = item.group_ids2.empty() ? 0 : static_cast<uint16_t>(item.group_ids2[0]);
            entry.dst_port_value = 0;
            entry.dst_port_mask = 0x0000; // 全端口通配
            entry.bin_prefix = std::string(16, '*');
            // ACTION: 使用原始的 action 字符串格式
            entry.Action = item.action.empty() ? "0x0000/0x0000" : item.action;
            entry.port_type = DST_Port_Type::WILDCARD; // 标记为全通配符

            dst_tcam_table.push_back(std::move(entry));
        } else {
            std::cerr << "[INFO] DST_Port_Item is not full range, skipping: "
                      << item.dst_lo << "-" << item.dst_hi << "\n";
        }
    }

    std::cerr << "[INFO] fill_full_range_items_to_dst_tcam produced "
              << dst_tcam_table.size() << " entries." << "\n";
}

static inline int prefix_fixed_len(const std::string &pref) {
    int cnt = 0;
    for (char c : pref) {
        if (c == '*') break;
        cnt++;
    }
    return cnt;
}

// 是否为“兄弟前缀”：长度相同且除最后一位外完全相同，最后1位相反
static inline bool are_sibling_prefixes(const std::string &a, const std::string &b) {
    int la = prefix_fixed_len(a);
    int lb = prefix_fixed_len(b);
    if (la == 0 || lb == 0) return false;
    if (la != lb) return false;
    // 比较前 (la-1) 位
    if (la == 1) {
        // 只有 1 位固定：比较空前缀（都相同 trivially），最后一位需不同
        return a[0] != b[0];
    }
    for (int i = 0; i < la-1; ++i) {
        if (a[i] != b[i]) return false;
    }
    // 最后一位必须不同 and both are '0' or '1'
    char la_char = a[la-1], lb_char = b[la-1];
    if ((la_char == '0' || la_char == '1') && (lb_char == '0' || lb_char == '1') && la_char != lb_char)
        return true;
    return false;
}

// 生成 parent prefix（把最后一位变成 '*'）
static inline std::string parent_prefix(const std::string &p) {
    int L = prefix_fixed_len(p);
    if (L == 0) return p; // already all *
    std::string s = p.substr(0, std::max(0, L-1));
    s += std::string(16 - (L-1), '*'); // 保持总长度为16位表示方式
    return s;
}

// 主合并函数
void merge_prefix_blocks(std::vector<BlockMeta>& blocks) {
    // 先按 group_id, src_item_idx, start 排序（确保只在同一 src_item 内合并）
    std::sort(blocks.begin(), blocks.end(), [](const BlockMeta &a, const BlockMeta &b) {
        if (a.group_id != b.group_id) return a.group_id < b.group_id;
        if (a.src_item_idx != b.src_item_idx) return a.src_item_idx < b.src_item_idx;
        return a.start < b.start;
    });

    std::vector<BlockMeta> out;
    out.reserve(blocks.size());

    size_t n = blocks.size();
    size_t i = 0;
    while (i < n) {
        // determine group range with same group_id and src_item_idx
        uint32_t gid = blocks[i].group_id;
        uint32_t src_idx = blocks[i].src_item_idx;
        size_t j = i;
        while (j < n && blocks[j].group_id == gid && blocks[j].src_item_idx == src_idx) ++j;

        // process [i, j) sequence
        std::vector<BlockMeta> stack;
        stack.reserve(j - i);

        for (size_t k = i; k < j; ++k) {
            const BlockMeta &bm = blocks[k];

            if (!bm.can_use_prefix) {
                // flush stack to out
                for (auto &s : stack) out.push_back(std::move(s));
                stack.clear();
                out.push_back(bm);
                continue;
            }

            // push a copy for possible merging
            stack.push_back(bm);

            // try merging as long as top two are mergeable
            while (stack.size() >= 2) {
                BlockMeta B = stack.back();
                BlockMeta A = stack[stack.size()-2];
                if (!(A.can_use_prefix && B.can_use_prefix && (A.end + 1 == B.start) && are_sibling_prefixes(A.bin_prefix, B.bin_prefix)))
                    break;

                // create merged block M
                BlockMeta M;
                M.group_id = A.group_id;
                M.src_item_idx = A.src_item_idx;
                M.start = A.start;
                M.end = B.end;
                M.can_use_prefix = true;
                M.bin_prefix = parent_prefix(A.bin_prefix);
                M.assigned = true;
                M.SP = A.SP;
                M.block_idx = A.block_idx;
                // GID2 handling: keep if equal, otherwise mark 0 (non-unique)
                M.group_id2 = (A.group_id2 == B.group_id2) ? A.group_id2 : 0;

                // pop two and push merged
                stack.pop_back();
                stack.pop_back();
                stack.push_back(std::move(M));
            }
        }

        // flush remaining stack
        for (auto &s : stack) out.push_back(std::move(s));
        stack.clear();

        i = j;
    }

    blocks.swap(out);
}

// DST 专用的合并函数：以 GroupID2 为主键并限制在相同 src_item_idx 内合并
void merge_prefix_blocks_for_dst(std::vector<BlockMeta_DST>& blocks) {
    // 按 group_id2, src_item_idx, start 排序
    std::sort(blocks.begin(), blocks.end(), [](const BlockMeta_DST &a, const BlockMeta_DST &b) {
        if (a.group_id2 != b.group_id2) return a.group_id2 < b.group_id2;
        if (a.src_item_idx != b.src_item_idx) return a.src_item_idx < b.src_item_idx;
        return a.start < b.start;
    });

    std::vector<BlockMeta_DST> out;
    out.reserve(blocks.size());

    size_t n = blocks.size();
    size_t i = 0;
    while (i < n) {
        uint32_t gid2 = blocks[i].group_id2;
        uint32_t src_idx = blocks[i].src_item_idx;
        size_t j = i;
        while (j < n && blocks[j].group_id2 == gid2 && blocks[j].src_item_idx == src_idx) ++j;

        std::vector<BlockMeta_DST> stack;
        stack.reserve(j - i);

        auto actions_equal = [](const std::vector<int> &a, const std::vector<int> &b) {
            if (a.size() != b.size()) return false;
            for (size_t k = 0; k < a.size(); ++k) if (a[k] != b[k]) return false;
            return true;
        };

        auto actions_union = [](const std::vector<int> &a, const std::vector<int> &b) {
            std::vector<int> res = a;
            for (int x : b) {
                if (std::find(res.begin(), res.end(), x) == res.end()) res.push_back(x);
            }
            return res;
        };

        for (size_t k = i; k < j; ++k) {
            const BlockMeta_DST &bm = blocks[k];

            if (!bm.can_use_prefix) {
                for (auto &s : stack) out.push_back(std::move(s));
                stack.clear();
                out.push_back(bm);
                continue;
            }

            stack.push_back(bm);

            while (stack.size() >= 2) {
                BlockMeta_DST B = stack.back();
                BlockMeta_DST A = stack[stack.size()-2];
                if (!(A.can_use_prefix && B.can_use_prefix && (A.end + 1 == B.start) && are_sibling_prefixes(A.bin_prefix, B.bin_prefix)))
                    break;

                BlockMeta_DST M;
                M.group_id2 = A.group_id2;
                M.group_id = A.group_id; // keep group_id from A but not used as key
                M.src_item_idx = A.src_item_idx;
                M.start = A.start;
                M.end = B.end;
                M.can_use_prefix = true;
                M.bin_prefix = parent_prefix(A.bin_prefix);
                M.assigned = true;
                M.SP = A.SP;
                M.block_idx = A.block_idx;
                // ACTION 合并：如果完全相同保留，否则做并集
                if (actions_equal(A.Action, B.Action)) M.Action = A.Action;
                else M.Action = actions_union(A.Action, B.Action);
                // action 字符串：如果相同则保留，否则使用第一个（或可以合并逻辑）
                if (A.action == B.action) M.action = A.action;
                else M.action = A.action;  // 使用第一个，或者可以根据需要实现更复杂的合并逻辑

                // group_id2 在组内相同，若出现不同则置 0（不过排序保证同组相同）
                M.group_id2 = (A.group_id2 == B.group_id2) ? A.group_id2 : 0;
                
                // 继承port_type：两个块应该有相同的port_type，取A的
                M.port_type = A.port_type;

                // pop two and push merged
                stack.pop_back();
                stack.pop_back();
                stack.push_back(std::move(M));
            }
        }

        for (auto &s : stack) out.push_back(std::move(s));
        stack.clear();

        i = j;
    }

    blocks.swap(out);
}

// 将 DST BlockMeta_DST 分配到 DST SRAM/TCAM 并输出文件
void assign_blocks_to_dst_sram_tcam(const std::vector<BlockMeta_DST>& blocks,
                                    std::vector<DST_SRAM_Table>& dst_sram_table,
                                    std::vector<DST_TCAM_Table>& dst_tcam_table)
{
    for (const auto &bm : blocks) {
        if (bm.assigned || bm.single_value || bm.can_use_prefix) {
            DST_TCAM_Table entry{};
            entry.GroupID2 = static_cast<uint16_t>(bm.group_id2);
            entry.bin_prefix = bm.bin_prefix;
            entry.Action = bm.action.empty() ? "0x0000/0x0000" : bm.action;
            entry.port_type = bm.port_type; // 保存端口类型
            dst_tcam_table.push_back(std::move(entry));
        } else {
            DST_SRAM_Table entry;
            entry.GroupID2 = static_cast<uint16_t>(bm.group_id2);
            entry.SP_Quotient = static_cast<uint16_t>(bm.SP);
            entry.Action = bm.action.empty() ? "0x0000/0x0000" : bm.action;
            entry.bitmap.clear();
            for (size_t k = 0; k < 32; ++k) if (bm.bitmap.test(k)) entry.bitmap.push_back(k);
            dst_sram_table.push_back(std::move(entry));
        }
    }

    // 输出到文件
    // 排序逻辑：首先按 GroupID2 排序，在同一 GroupID2 内：
    // 按端口类型排序：点(POINT=0) -> 短区间(SHORT_RANGE=1) -> 长区间(LONG_RANGE=2) -> 全通配符(WILDCARD=3)
    std::stable_sort(dst_tcam_table.begin(), dst_tcam_table.end(), [](const DST_TCAM_Table &a, const DST_TCAM_Table &b){
        if (a.GroupID2 != b.GroupID2) {
            return a.GroupID2 < b.GroupID2;
        }
        
        // 同一 GroupID2 内，按端口类型排序（枚举值直接反映优先级）
        int a_type_order = static_cast<int>(a.port_type);
        int b_type_order = static_cast<int>(b.port_type);
        
        if (a_type_order != b_type_order) {
            return a_type_order < b_type_order;
        }
        
        // 相同类型内，按bin_prefix字典序排序
        return a.bin_prefix < b.bin_prefix;
    });
    std::ofstream dtcam("src/output/DST_TCAM_Table.txt");
    dtcam << "GroupID2    DstPort             Action \n";
    dtcam.close();

    std::sort(dst_sram_table.begin(), dst_sram_table.end(), [](const DST_SRAM_Table &a, const DST_SRAM_Table &b){
        if (a.GroupID2 != b.GroupID2) return a.GroupID2 < b.GroupID2;
        return a.SP_Quotient < b.SP_Quotient;
    });
    std::ofstream dsram("src/output/DST_SRAM_Table.txt");
    dsram << std::left << std::setw(12) << "GroupID2" << std::setw(12) << "SP_Quotient" << std::setw(40) << "Bitmap32" << std::setw(10) << "Action" << "\n";
    for (const auto &e : dst_sram_table) {
        std::bitset<32> b;
        for (size_t idx : e.bitmap) if (idx < 32) b.set(idx);
        std::string s;
        for (int i = 0; i < 32; ++i) s += b[i] ? '1' : '0';
        dsram << std::left << std::setw(12) << e.GroupID2 << std::setw(12) << e.SP_Quotient << std::setw(40) << s << std::setw(10) << e.Action << "\n";
    }
    dsram.close();

    std::cerr << "[INFO] DST Tables exported. TCAM entries=" << dst_tcam_table.size() << ", SRAM entries=" << dst_sram_table.size() << "\n";
}


void output_sram_tcam_tables(
    std::vector<SRC_TCAM_Table>& src_tcam_table,
    std::vector<SRC_SRAM_Table>& src_sram_table)
{
    auto bitmap_to_32bit_string = [](const std::vector<size_t>& indexes) {
        std::bitset<32> b;
        for (size_t idx : indexes) {
            if (idx < 32) b.set(idx);
        }
        std::string s;
        // 按 offset 0..31 的顺序输出，使得字符串左侧对应 block 内低偏移
        for (int i = 0; i < 32; ++i) s += b[i] ? '1' : '0';
        return s;
    };

    // -------- TCAM 输出 --------
    // 排序逻辑：首先按 GroupID1 排序，在同一 GroupID1 内：
    // 1. 单点（无*）优先
    // 2. 范围内部：普通范围按起始顺序，超长范围（全*或前缀<=3）放在最后
    std::sort(src_tcam_table.begin(), src_tcam_table.end(),
        [](const SRC_TCAM_Table &a, const SRC_TCAM_Table &b) {
            if (a.GroupID1 != b.GroupID1) return a.GroupID1 < b.GroupID1;
            // 同一 G-ID1 内，判断是否为单点（无*）还是范围（有*）
            bool a_is_single_point = (a.bin_prefix.find('*') == std::string::npos);
            bool b_is_single_point = (b.bin_prefix.find('*') == std::string::npos);
            // 单点排在前面（优先级更高）
            if (a_is_single_point != b_is_single_point) {
                return a_is_single_point; // a 是单点时返回 true（排在前面）
            }
            
            // 如果都是单点，按GroupID2排序，然后按bin_prefix排序
            if (a_is_single_point && b_is_single_point) {
                if (a.GroupID2 != b.GroupID2) return a.GroupID2 < b.GroupID2;
                return a.bin_prefix < b.bin_prefix;
            }
            
            // 如果都是范围，判断是否为超长范围（全*或前缀<=3个固定位）
            bool a_is_full_wildcard = (a.bin_prefix.size() == 16 && 
                                       a.bin_prefix.find_first_not_of('*') == std::string::npos);
            bool b_is_full_wildcard = (b.bin_prefix.size() == 16 && 
                                       b.bin_prefix.find_first_not_of('*') == std::string::npos);
            int a_fixed_len = prefix_fixed_len(a.bin_prefix);
            int b_fixed_len = prefix_fixed_len(b.bin_prefix);
            bool a_is_long_range = a_is_full_wildcard || (a_fixed_len <= 3);
            bool b_is_long_range = b_is_full_wildcard || (b_fixed_len <= 3);
            
            // 超长范围放在最后
            if (a_is_long_range != b_is_long_range) {
                return !a_is_long_range;  // a不是超长范围时返回true（a排在前面）
            }
            
            // 如果都是超长范围，全*放在最后
            if (a_is_long_range && b_is_long_range) {
                if (a_is_full_wildcard != b_is_full_wildcard) {
                    return !a_is_full_wildcard;  // a不是全*时返回true（a排在前面）
                }
            }
            
            // 普通范围或都是超长范围（但都是全*或都不是全*），先按GroupID2排序，再按bin_prefix排序
            if (a.GroupID2 != b.GroupID2) return a.GroupID2 < b.GroupID2;
            return a.bin_prefix < b.bin_prefix;
        }
    );

    std::ofstream tcam_file("src/output/SRC_TCAM_Table.txt");
    tcam_file << std::left
              << std::setw(20) << "GroupID1"
              << std::setw(40) << "SrcPort"
              << std::setw(20) << "GroupID2" << "\n";

    for (const auto &e : src_tcam_table) {
        tcam_file << std::left
                  << std::setw(20) << e.GroupID1
                  << std::setw(40) << e.bin_prefix
                  << std::setw(20) << e.GroupID2 << "\n";
    }
    tcam_file.close();

    // -------- SRAM 输出 --------
    // 排序逻辑：首先按 GroupID1 排序，在同一 GroupID1 内，SP_Quotient=0 且可能覆盖全范围的放在最后
    // 注意：SRAM 中 0-65535 会被拆分成多个 block，但 SP_Quotient=0 的 block 可能包含 0-31
    // 这里我们简单按 SP_Quotient 排序，0-65535 相关的 block 通常 SP_Quotient 较小
    std::sort(src_sram_table.begin(), src_sram_table.end(),
        [](const SRC_SRAM_Table &a, const SRC_SRAM_Table &b) {
            if (a.GroupID1 != b.GroupID1) return a.GroupID1 < b.GroupID1;
            if (a.SP_Quotient != b.SP_Quotient) return a.SP_Quotient < b.SP_Quotient;
            return a.GroupID2 < b.GroupID2;
        }
    );

    std::ofstream sram_file("src/output/SRC_SRAM_Table.txt");
    sram_file << std::left
              << std::setw(20) << "GroupID1"
              << std::setw(22) << "SP_Quotient"
              << std::setw(50) << "Bitmap32"
              << std::setw(10) << "GroupID2" << "\n";

    for (const auto &e : src_sram_table) {
        sram_file << std::left
                  << std::setw(20) << e.GroupID1
                  << std::setw(22) << e.SP_Quotient
                  << std::setw(50) << bitmap_to_32bit_string(e.bitmap)
                  << std::setw(10) << e.GroupID2 << "\n";
    }
    sram_file.close();

    std::cerr << "[INFO] Tables exported. "
              << "TCAM entries=" << src_tcam_table.size()
              << ", SRAM entries=" << src_sram_table.size() << "\n";
}


void assign_blocks_to_sram_tcam(
    const std::vector<BlockMeta>& blocks,
    std::vector<SRC_SRAM_Table>& src_sram_table,
    std::vector<SRC_TCAM_Table>& src_tcam_table)
{
    for (const auto &bm : blocks) {
        if ( bm.assigned || bm.single_value || bm.can_use_prefix ) {
            // 分配到 TCAM
            SRC_TCAM_Table entry{};
            entry.GroupID1 = static_cast<uint16_t>(bm.group_id);
            entry.bin_prefix = bm.bin_prefix;
            entry.GroupID2 = static_cast<uint16_t>(bm.group_id2);
            src_tcam_table.push_back(std::move(entry));
        } else {
            // 分配到 SRAM
            SRC_SRAM_Table entry;
            entry.GroupID1 = static_cast<uint16_t>(bm.group_id);
            entry.SP_Quotient = static_cast<uint16_t>(bm.SP);
            entry.GroupID2 = static_cast<uint16_t>(bm.group_id2);

            entry.bitmap.clear();
            for (size_t k = 0; k < 32; ++k) {
                if (bm.bitmap.test(k)) entry.bitmap.push_back(k);
            }
            src_sram_table.push_back(std::move(entry));
        }
    }

    // 合并逻辑：将 G-ID1 相同，bin_prefix 相同，G-ID2 相同的 TCAM 表项合并（去重）
    {
        std::map<std::tuple<uint16_t, std::string, uint16_t>, SRC_TCAM_Table> tcam_map;
        for (auto& entry : src_tcam_table) {
            auto key = std::make_tuple(entry.GroupID1, entry.bin_prefix, entry.GroupID2);
            // 如果已存在，则跳过（保留第一个）
            if (tcam_map.find(key) == tcam_map.end()) {
                tcam_map[key] = entry;
            }
        }
        src_tcam_table.clear();
        for (auto& [key, entry] : tcam_map) {
            src_tcam_table.push_back(entry);
        }
    }

    // 合并逻辑：将 G-ID1 相同，SP_Quotient 相同，G-ID2 相同的 SRAM 表项合并（合并 bitmap）
    {
        std::map<std::tuple<uint16_t, uint16_t, uint16_t>, SRC_SRAM_Table> sram_map;
        for (auto& entry : src_sram_table) {
            auto key = std::make_tuple(entry.GroupID1, entry.SP_Quotient, entry.GroupID2);
            auto it = sram_map.find(key);
            if (it == sram_map.end()) {
                sram_map[key] = entry;
            } else {
                // 合并 bitmap：取并集
                std::set<size_t> bitmap_set;
                for (size_t idx : it->second.bitmap) bitmap_set.insert(idx);
                for (size_t idx : entry.bitmap) bitmap_set.insert(idx);
                it->second.bitmap.clear();
                for (size_t idx : bitmap_set) it->second.bitmap.push_back(idx);
            }
        }
        src_sram_table.clear();
        for (auto& [key, entry] : sram_map) {
            src_sram_table.push_back(entry);
        }
    }

    output_sram_tcam_tables(src_tcam_table, src_sram_table);
}

// 将 merged_output 格式的 mateifno 拆分为以 src 为主和以 dst 为主的两个列表
void split_mateinfo_into_src_dst(
    const std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem> &mateifno,
    std::vector<Mate_SRC_LIST> &mate_src,
    std::vector<Mate_DST_LIST> &mate_dst)
{
    mate_src.clear();
    mate_dst.clear();

    mate_src.reserve(mateifno.size());
    mate_dst.reserve(mateifno.size());

    for (const auto &kv : mateifno) {
        const MergedItem &mi = kv.second;

        Mate_SRC_LIST s;
        s.group_ids = mi.group_ids;
        s.src_lo = mi.src_lo;
        s.src_hi = mi.src_hi;
        s.idx_list = mi.idx_list;
        s.initnum_list = mi.initnum_list;

        Mate_DST_LIST d;
        d.group_ids = mi.group_ids;
        d.dst_lo = mi.dst_lo;
        d.dst_hi = mi.dst_hi;
        d.idx_list = mi.idx_list;
        d.initnum_list = mi.initnum_list;
        d.action = mi.action;  // 传递 action 字段

        mate_src.push_back(std::move(s));
        mate_dst.push_back(std::move(d));
    }
}

// 给 src 表条目分配顺序的 GID2（第二个 group id）
// ★ 修改：使用idx_list作为GID2，而不是重新分配顺序ID
void create_GID2_for_src_port_table(std::vector<SRC_Port_Item> &items, const std::vector<Mate_SRC_LIST> &mate_src) {
    size_t n = std::min(items.size(), mate_src.size());
    for (size_t i = 0; i < n; ++i) {
        if (!mate_src[i].idx_list.empty()) {
            int gid2 = mate_src[i].idx_list[0];  // ★ 使用idx_list[0]作为GID2
            if (items[i].group_ids2.size() >= 1) items[i].group_ids2[0] = gid2;
            else items[i].group_ids2.push_back(gid2);
        }
    }
}

// 给 dst 表条目分配顺序的 GID2（对称于 src）
// ★ 修改：使用idx_list作为GID2
void create_GID2_for_dst_port_table(std::vector<DST_Port_Item> &items, const std::vector<Mate_DST_LIST> &mate_dst) {
    size_t n = std::min(items.size(), mate_dst.size());
    for (size_t i = 0; i < n; ++i) {
        if (!mate_dst[i].idx_list.empty()) {
            int gid2 = mate_dst[i].idx_list[0];  // ★ 使用idx_list[0]作为GID2
            if (items[i].group_ids2.size() >= 1) items[i].group_ids2[0] = gid2;
            else items[i].group_ids2.push_back(gid2);
        }
    }
}

// Build SRC_Port_Item list from meta_src_list, assign GID2s and return the items
std::vector<SRC_Port_Item> build_src_items_from_meta_src_list(const std::vector<MergedItem> &meta_src_list) {
    std::vector<SRC_Port_Item> src_items;
    src_items.reserve(meta_src_list.size());
    for (const auto &mi : meta_src_list) {
        SRC_Port_Item it;
        it.group_ids1 = mi.group_ids;
        it.src_lo = mi.src_lo;
        it.src_hi = mi.src_hi;
        // group_ids2 empty for now; will be filled by create_GID2_for_src_port_table
        src_items.push_back(std::move(it));
    }

    return src_items;
}

// Build SRC_Port_Item list directly from Mate_SRC_LIST (avoid intermediate MergedItem)
std::vector<SRC_Port_Item> build_src_items_from_mate_src_list(const std::vector<Mate_SRC_LIST> &mate_src) {
    std::vector<SRC_Port_Item> src_items;
    src_items.reserve(mate_src.size());
    for (const auto &s : mate_src) {
        SRC_Port_Item it;
        it.group_ids1 = s.group_ids;
        it.src_lo = s.src_lo;
        it.src_hi = s.src_hi;
        // group_ids2 will be assigned later
        src_items.push_back(std::move(it));
    }
    return src_items;
}

// Build DST_Port_Item list directly from Mate_DST_LIST (avoid intermediate MergedItem)
// 判断端口类型：点、短区间、长区间
DST_Port_Type classify_dst_port_type(uint32_t dst_lo, uint32_t dst_hi) {
    // 判断是否为全通配符 0-65535
    if (dst_lo == 0 && dst_hi == 65535) {
        return DST_Port_Type::WILDCARD;
    }
    
    // 判断是否为点（单个点值）
    if (dst_lo == dst_hi) {
        return DST_Port_Type::POINT;
    }
    
    // 判断是否为长区间：1025-65535 或 5001-65535
    if ((dst_lo == 1025 && dst_hi == 65535) || 
        (dst_lo == 5001 && dst_hi == 65535)) {
        return DST_Port_Type::LONG_RANGE;
    }
    
    // 其他情况为短区间
    return DST_Port_Type::SHORT_RANGE;
}

std::vector<DST_Port_Item> build_dst_items_from_mate_dst_list(const std::vector<Mate_DST_LIST> &mate_dst) {
    std::vector<DST_Port_Item> dst_items;
    dst_items.reserve(mate_dst.size());
    for (const auto &d : mate_dst) {
        DST_Port_Item it;
        it.group_ids1 = d.group_ids;
        it.dst_lo = d.dst_lo;
        it.dst_hi = d.dst_hi;
        it.action = d.action;  // 保存原始的 action 字符串格式
        // 判断并设置端口类型
        it.port_type = classify_dst_port_type(d.dst_lo, d.dst_hi);
        // Initialize Action from mate_dst.action
        // Note: DST_Port_Item::Action is std::vector<int> for action IDs,
        // but d.action is now std::string. We need to create a mapping or skip this.
        // For now, we'll skip it since Action is used for TCAM/SRAM tables which need numeric IDs.
        // The actual action string is preserved in MergedItem and will be written to meta_merged.txt
        // it.Action.push_back(d.action);
        // group_ids2 will be assigned later if needed
        dst_items.push_back(std::move(it));
    }
    return dst_items;
}

// Apply assigned GID2s from src_items back into meta_src_list (update group_ids)
void apply_src_items_back_to_meta(std::vector<MergedItem> &meta_src_list, const std::vector<SRC_Port_Item> &src_items) {
    size_t n = std::min(meta_src_list.size(), src_items.size());
    for (size_t i = 0; i < n; ++i) {
        // preserve other fields in meta_src_list, but update group_ids
        meta_src_list[i].group_ids = src_items[i].group_ids1;
        if (!src_items[i].group_ids2.empty()) {
            int gid2 = src_items[i].group_ids2[0];
            if (meta_src_list[i].group_ids.size() >= 2) meta_src_list[i].group_ids[1] = gid2;
            else meta_src_list[i].group_ids.push_back(gid2);
        }
    }
}

void output_src_items_to_txt(const std::vector<SRC_Port_Item> &src_items)
{
    std::ofstream fout("src/output/src_items.txt");
    if (!fout) {
        std::cerr << "Error: cannot open src_items.txt\n";
        return;
    }

    fout << "GID1\tSrc_lo\tSrc_hi\tGID2\n";

    for (const auto &s : src_items) {

        // stringify group id vectors
        std::ostringstream g1oss, g2oss;
        for (size_t i = 0; i < s.group_ids1.size(); ++i) {
            if (i) g1oss << ",";
            g1oss << s.group_ids1[i];
        }
        for (size_t i = 0; i < s.group_ids2.size(); ++i) {
            if (i) g2oss << ",";
            g2oss << s.group_ids2[i];
        }

        fout << std::left
            << std::setw(12) << g1oss.str()
            << std::setw(12) << s.src_lo
            << std::setw(12) << s.src_hi
            << std::setw(12) << g2oss.str()
            << "\n";
    }

    fout.close();
    std::cout << "[INFO] src_items.txt saved.\n";
}

//-------------------- Step 9: Main function to build SRC port tables --------------------
void create_Table_for_port(
    const vector<PortRule>& /* port_table */,
    const vector<IPRule>& /* merged_ip_table */,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& mateifno
){  
    vector<Mate_SRC_LIST> mate_src;
    vector<Mate_DST_LIST> mate_dst;

    split_mateinfo_into_src_dst(mateifno, mate_src, mate_dst);

    // build SRC_Port_Item list directly from mate_src and assign GID2s
    auto src_items = build_src_items_from_mate_src_list(mate_src);
    // assign GID2 from idx_list (meta_merged.txt row number)
    create_GID2_for_src_port_table(src_items, mate_src);

    output_src_items_to_txt(src_items);
    //create tcam sram for SRC port table
    std::vector<SRC_SRAM_Table> src_sram_table;
    std::vector<SRC_TCAM_Table> src_tcam_table;

    auto split_result_src = split_port_range_into_blocks_for_src(src_items);
    auto &blocks_src = split_result_src.blocks;
    auto &full_range_items_src = split_result_src.full_range_items_src;

    fill_full_range_items_to_src_tcam(full_range_items_src, src_tcam_table);

    merge_prefix_blocks(blocks_src);

    assign_blocks_to_sram_tcam(blocks_src, src_sram_table, src_tcam_table);

    //create tcam sram for DST port table;
    std::vector<DST_SRAM_Table> dst_sram_table;
    std::vector<DST_TCAM_Table> dst_tcam_table;

    auto dst_items = build_dst_items_from_mate_dst_list(mate_dst);
    // assign GID2 from idx_list (meta_merged.txt row number)
    create_GID2_for_dst_port_table(dst_items, mate_dst);
    auto split_result_dst = split_port_range_into_blocks_for_dst(dst_items);
    auto &blocks_dst = split_result_dst.blocks;
    auto &full_range_items_dst = split_result_dst.full_range_items_dst;

    fill_full_range_items_to_dst_tcam(full_range_items_dst, dst_tcam_table);
    // 对剩余 blocks 做合并（以 GID2 为主）并分配到 DST TCAM/SRAM
    merge_prefix_blocks_for_dst(blocks_dst);

    // assign DST blocks to DST SRAM/TCAM (moved to standalone function)
    assign_blocks_to_dst_sram_tcam(blocks_dst, dst_sram_table, dst_tcam_table);

}

void Map_cell_to_origID(
    const vector<Rmax_IPRule>& rmax_merged_ip_table,
    const vector<size_t>& idx_list,
    vector<size_t>& out_orig_ids)
{
    out_orig_ids.clear();
    unordered_set<size_t> uniq;

    for (size_t mid : idx_list) {
        if (mid >= rmax_merged_ip_table.size()) continue;

        const auto& R = rmax_merged_ip_table[mid];
        for (size_t orig : R.merged_R) {
            uniq.insert(orig);   // 去重
        }
    }

    out_orig_ids.assign(uniq.begin(), uniq.end());
}


void Search_Rmax_Intersection_per_proto(
    vector<Rmax_IPRule>& Rmax_merged_ip_table,
    vector<IntersectionCell>& Rmax_intersections)
{
    // proto -> unique rmax_id set
    std::map<uint8_t, std::unordered_set<size_t>> proto_to_rmax_ids;

    // rmax_id -> representative rule index
    std::unordered_map<size_t, size_t> rmax_id_to_rule_idx;

    // 1. 提取 proto / rmax_id 关系
    for (size_t i = 0; i < Rmax_merged_ip_table.size(); ++i) {
        const auto& rule = Rmax_merged_ip_table[i];
        proto_to_rmax_ids[rule.proto].insert(rule.rmax_id);

        // 只记录第一次出现的 rule 作为该 rmax 的代表
        if (!rmax_id_to_rule_idx.count(rule.rmax_id)) {
            rmax_id_to_rule_idx[rule.rmax_id] = i;
        }
    }

    size_t total_intersections = 0;

    // 2. 按 proto 处理
    for (const auto& [proto, rmax_ids] : proto_to_rmax_ids) {

        // 规则 1：只有一个 Rmax，直接跳过
        if (rmax_ids.size() <= 1) {
            continue;
        }
        
        // 可选：全局 Rmax 检测（如你需要）
        bool has_global_rmax = false;
        for (size_t rmax_id : rmax_ids) {
            const auto& r =
                Rmax_merged_ip_table[rmax_id_to_rule_idx[rmax_id]];
            if (r.src_ip_lo == 0 && r.src_ip_hi == UINT32_MAX &&
                r.dst_ip_lo == 0 && r.dst_ip_hi == UINT32_MAX) {
                has_global_rmax = true;
                break;
            }
        }
        if (has_global_rmax) {
            continue;
        }

        // 3. Rmax 之间做相交
        std::vector<size_t> rmax_list(rmax_ids.begin(), rmax_ids.end());

        for (size_t i = 0; i < rmax_list.size(); ++i) {
            for (size_t j = i + 1; j < rmax_list.size(); ++j) {

                size_t id1 = rmax_list[i];
                size_t id2 = rmax_list[j];

                const auto& rmax1 =
                    Rmax_merged_ip_table[rmax_id_to_rule_idx[id1]];
                const auto& rmax2 =
                    Rmax_merged_ip_table[rmax_id_to_rule_idx[id2]];

                bool src_overlap =
                    !(rmax1.src_ip_hi < rmax2.src_ip_lo ||
                      rmax2.src_ip_hi < rmax1.src_ip_lo);
                bool dst_overlap =
                    !(rmax1.dst_ip_hi < rmax2.dst_ip_lo ||
                      rmax2.dst_ip_hi < rmax1.dst_ip_lo);

                if (!src_overlap || !dst_overlap)
                    continue;

                // 4. 构造交集 cell
                    IntersectionCell cell;
                    cell.proto = proto;
                    
                    cell.src_lo = std::max(rmax1.src_ip_lo, rmax2.src_ip_lo);
                    cell.src_hi = std::min(rmax1.src_ip_hi, rmax2.src_ip_hi);
                    cell.dst_lo = std::max(rmax1.dst_ip_lo, rmax2.dst_ip_lo);
                    cell.dst_hi = std::min(rmax1.dst_ip_hi, rmax2.dst_ip_hi);
                    
                // 注意：这里存的是 rmax_id，不是 rule index
                cell.rmax_id = id1; // 或根据你后续逻辑决定
                cell.rule_indices = {id1, id2};

                // ★ Extraction 存储 Rmax_merged_ip_table 索引，不在这里映射为原始规则ID
                // 统一在 Generate_cell_GID_to_metainfo 中映射
                // 修复：id1, id2 是 rmax_id，需要通过 rmax_id_to_rule_idx 转换为 Rmax_merged_ip_table 索引
                cell.Extraction = {rmax_id_to_rule_idx[id1], rmax_id_to_rule_idx[id2]};

                cell.priority = 1;

                Rmax_intersections.push_back(cell);
                total_intersections++;
            }
        }
    }

    cout << "[DEBUG] Generated " << total_intersections << " Rmax intersections" << endl;
}

void Split_SrcPort_Per_GID(int gid, 
    std::vector<MergedItem*>& items,
    std::vector<MergedItem>& src_out_items,
    int& next_idx,  // ★ 每个 G-ID 内部使用的局部 idx 计数器（从 0 开始）
    const std::vector<PortRule>& port_table)  // ★ 添加 port_table 参数以获取优先级信息
{
    src_out_items.clear();

    // ================================
    // Step 0: 按是否为 0–65535 分类
    // ================================    
    std::vector<MergedItem*> full_range_items;
    std::vector<MergedItem*> normal_items;

    for (auto* it : items) {
        if (it->src_lo == 0 && it->src_hi == 65535)
            full_range_items.push_back(it);
        else
            normal_items.push_back(it);
    }

    // ================================
    // Step 1: 不需要拆分的快速返回
    // ================================

    // 1.1 只有 0 或 1 个非全覆盖区间
    if (normal_items.size() <= 1) {
        for (auto* it : items)
            src_out_items.push_back(*it);
        return;
    }

    // 1.2 非全覆盖区间之间无重叠
    std::sort(normal_items.begin(), normal_items.end(),
              [](auto* a, auto* b) {
                  return a->src_lo < b->src_lo;
              });

    bool has_overlap = false;
    for (size_t i = 1; i < normal_items.size(); ++i) {
        if (normal_items[i]->src_lo <= normal_items[i - 1]->src_hi) {
            has_overlap = true;
            break;
        }
    }

    if (!has_overlap) {
        for (auto* it : items)
            src_out_items.push_back(*it);
        return;
    }

    // ================================
    // Step 2: 生成 SRC 拆分切点（端点原子化）
    // ================================
    std::set<uint32_t> cut_points;

    for (auto* it : normal_items) {
        uint32_t lo = it->src_lo;
        uint32_t hi = it->src_hi;

        // 左端点
        cut_points.insert(lo);
        if (lo + 1 <= hi)
            cut_points.insert(lo + 1);

        // 右端点
        cut_points.insert(hi);
        if (hi + 1 <= 65535)
            cut_points.insert(hi + 1);
    }

    // ================================
    // Step 3: 生成最小 SRC 原子区间
    // ================================
    std::vector<std::pair<uint32_t, uint32_t>> src_segments;

    auto cp_it = cut_points.begin();
    while (cp_it != cut_points.end()) {
        uint32_t seg_lo = *cp_it;
        ++cp_it;
        if (cp_it == cut_points.end()) break;

        uint32_t seg_hi = *cp_it - 1;
        if (seg_lo <= seg_hi)
            src_segments.emplace_back(seg_lo, seg_hi);
    }

    // ================================
    // Step 4: 为每个 SRC 原子区间收集覆盖它的 item
    // ================================
    struct Src_Temp_Item{
        uint32_t src_lo;
        uint32_t src_hi;
        std::vector<MergedItem*> covered_items;
        int assigned_idx;  // ★ 为这个 SRC 区间分配的 idx
    };

    // 辅助函数：比较两个覆盖集合是否相同（基于 idx_list）
    auto covers_equal = [](const std::vector<MergedItem*>& a, const std::vector<MergedItem*>& b) {
        if (a.size() != b.size()) return false;
        // 收集所有 idx_list 并排序比较
        std::set<int> idxs_a, idxs_b;
        for (auto* item : a) {
            for (int idx : item->idx_list) idxs_a.insert(idx);
        }
        for (auto* item : b) {
            for (int idx : item->idx_list) idxs_b.insert(idx);
        }
        return idxs_a == idxs_b;
    };

    std::vector<Src_Temp_Item> temp_segments;
    int local_next_idx = 0;  // ★ 修复：每个 G-ID 内部从 0 开始计数

    for (auto& [seg_lo, seg_hi] : src_segments) {
        std::vector<MergedItem*> covered;
    
        // 普通区间
        for (auto* it : normal_items) {
            if (it->src_lo <= seg_lo && it->src_hi >= seg_hi)
                covered.push_back(it);
        }
    
        // ★ 修复：0-65535 不应该参与拆分，应该单独处理
        // 不在这里添加 full_range_items，它们会在最后单独添加
    
        if (covered.empty())
            continue;
    
        // ================================
        // 合并覆盖相同的连续区间
        // ================================
        // ★ 修复：为每个 (SRC区间, 覆盖规则集合) 分配唯一的 idx
        // 如果覆盖相同，使用相同的 idx；否则分配新的 idx
        int assigned_idx;
        
        // 检查是否与前一段覆盖相同
        if (!temp_segments.empty() && covers_equal(temp_segments.back().covered_items, covered)) {
            // 与前一段覆盖相同 → 扩展前一段，使用相同的 idx
            temp_segments.back().src_hi = seg_hi;
            assigned_idx = temp_segments.back().assigned_idx;
        } else {
            // 新的覆盖组合 → 分配新的 idx（局部计数器）
            assigned_idx = local_next_idx++;
            temp_segments.push_back({seg_lo, seg_hi, covered, assigned_idx});
        }
    }
        // ================================
        // Step 5: 生成新的 MergedItem（包含 DST 原子化分割和优先级选择）
        // ================================
    for (auto& seg : temp_segments) {
        // ★ 修复：按照正确的逻辑处理 DST 区间
        // 1. 对于当前 SRC 段，收集所有覆盖它的规则的 DST 区间
        // 2. 对这些 DST 区间进行原子化分割（类似 SRC 的原子化分割）
        // 3. 为每个 DST 原子区间选择覆盖它的规则中优先级最高的 action
        // 4. 最后合并相邻的、action 相同的 DST 区间（在 Step 8 中完成）
        
        // Step 5.1: 收集所有覆盖当前 SRC 段的规则的 DST 区间端点
        std::set<uint32_t> dst_cut_points;
        for (auto* orig : seg.covered_items) {
            dst_cut_points.insert(orig->dst_lo);
            if (orig->dst_lo + 1 <= orig->dst_hi)
                dst_cut_points.insert(orig->dst_lo + 1);
            dst_cut_points.insert(orig->dst_hi);
            if (orig->dst_hi + 1 <= 65535)
                dst_cut_points.insert(orig->dst_hi + 1);
        }
        
        // Step 5.2: 生成 DST 原子区间（类似 SRC 的原子化分割）
        std::vector<std::pair<uint32_t, uint32_t>> dst_segments;
        auto dst_cp_it = dst_cut_points.begin();
        while (dst_cp_it != dst_cut_points.end()) {
            uint32_t dst_seg_lo = *dst_cp_it;
            ++dst_cp_it;
            if (dst_cp_it == dst_cut_points.end()) break;
            
            uint32_t dst_seg_hi = *dst_cp_it - 1;
            if (dst_seg_lo <= dst_seg_hi)
                dst_segments.emplace_back(dst_seg_lo, dst_seg_hi);
        }
        
        // Step 5.3: 为每个 DST 原子区间选择最高优先级的动作
        for (auto& [dst_seg_lo, dst_seg_hi] : dst_segments) {
            // 收集所有覆盖当前 DST 原子区间的规则
            std::vector<MergedItem*> covering_items;
            for (auto* orig : seg.covered_items) {
                if (orig->dst_lo <= dst_seg_lo && orig->dst_hi >= dst_seg_hi) {
                    covering_items.push_back(orig);
                }
            }
            
            if (covering_items.empty())
                continue;
            
            // 选择优先级最高的动作（priority 越小优先级越高，lower priority value = higher priority）
            // 在 ACL 规则中，规则编号越小（priority 越小），优先级越高（先匹配）
            std::string best_action = "";
            uint32_t best_priority = UINT32_MAX;  // 初始化为最大值，寻找最小的 priority
            std::vector<int> best_initnum_list;
            
            for (auto* orig : covering_items) {
                // 从 port_table 中获取优先级（通过 initnum_list 中的 rid）
                uint32_t min_priority = UINT32_MAX;
                for (int initnum : orig->initnum_list) {
                    if (initnum >= 0 && static_cast<size_t>(initnum) < port_table.size()) {
                        uint32_t prio = port_table[initnum].priority;
                        if (prio < min_priority)
                            min_priority = prio;
                    }
                }
                
                // 选择优先级最高的规则的动作（priority 越小优先级越高）
                if (min_priority < best_priority) {
                    best_priority = min_priority;
                    best_action = orig->action;
                    best_initnum_list = orig->initnum_list;
                } else if (min_priority == best_priority && min_priority < UINT32_MAX) {
                    // 优先级相同，合并 initnum_list
                    std::set<int> initnum_set(best_initnum_list.begin(), best_initnum_list.end());
                    for (int initnum : orig->initnum_list) {
                        initnum_set.insert(initnum);
                    }
                    best_initnum_list.assign(initnum_set.begin(), initnum_set.end());
                }
            }
            
            // 如果没有找到优先级信息，使用第一个规则的动作
            if (best_priority == UINT32_MAX && !covering_items.empty()) {
                best_action = covering_items[0]->action;
                best_initnum_list = covering_items[0]->initnum_list;
            }
            
            // 创建新的 MergedItem
            MergedItem final_item;
            final_item.group_ids = seg.covered_items[0]->group_ids;  // 使用第一个规则的 group_ids
            final_item.src_lo = seg.src_lo;
            final_item.src_hi = seg.src_hi;
            final_item.dst_lo = dst_seg_lo;
            final_item.dst_hi = dst_seg_hi;
            final_item.idx_list = {seg.assigned_idx};
            final_item.initnum_list = best_initnum_list;
            final_item.action = best_action;
            
            src_out_items.push_back(std::move(final_item));
        }
    }
    
    // ================================
    // Step 8: 合并相同 SRC 区间内相邻且 action 相同的 DST 区间
    // ================================
    if (!src_out_items.empty()) {
        // 按 SRC 区间、idx_list、action 排序，然后按 DST 区间排序
        std::sort(src_out_items.begin(), src_out_items.end(),
            [](const MergedItem& a, const MergedItem& b) {
                // 先按 SRC 区间排序
                if (a.src_lo != b.src_lo) return a.src_lo < b.src_lo;
                if (a.src_hi != b.src_hi) return a.src_hi < b.src_hi;
                // 再按 idx_list 排序
                if (a.idx_list != b.idx_list) return a.idx_list < b.idx_list;
                // 再按 action 排序
                if (a.action != b.action) return a.action < b.action;
                // 最后按 DST 区间排序
                if (a.dst_lo != b.dst_lo) return a.dst_lo < b.dst_lo;
                return a.dst_hi < b.dst_hi;
            });
        
        std::vector<MergedItem> merged_items;
        merged_items.reserve(src_out_items.size());
        
        for (size_t i = 0; i < src_out_items.size(); ++i) {
            if (merged_items.empty()) {
                merged_items.push_back(src_out_items[i]);
                continue;
            }
            
            auto& last = merged_items.back();
            const auto& curr = src_out_items[i];
            
            // 检查是否可以合并：
            // 1. 相同的 SRC 区间
            // 2. 相同的 idx_list
            // 3. 相同的 action
            // 4. DST 区间相邻（last.dst_hi + 1 == curr.dst_lo）
            bool can_merge = 
                (last.src_lo == curr.src_lo && last.src_hi == curr.src_hi) &&
                (last.idx_list == curr.idx_list) &&
                (last.action == curr.action) &&
                (last.dst_hi + 1 == curr.dst_lo);
            
            if (can_merge) {
                // 合并：扩展 DST 区间，合并 initnum_list
                last.dst_hi = curr.dst_hi;
                // 合并 initnum_list（去重）
                std::set<int> initnum_set(last.initnum_list.begin(), last.initnum_list.end());
                for (int initnum : curr.initnum_list) {
                    initnum_set.insert(initnum);
                }
                last.initnum_list.assign(initnum_set.begin(), initnum_set.end());
            } else {
                // 不能合并，添加新项
                merged_items.push_back(curr);
            }
        }
        
        src_out_items = std::move(merged_items);
    }
    
    // ★ 修复：0-65535 区间应该单独添加，不参与拆分
    // 对于每个 0-65535 的 item，使用最后一个正常区间的 idx（如果有的话）
    // 如果没有正常区间，使用 0
    for (auto* full_item : full_range_items) {
        MergedItem full_range_copy = *full_item;
        // 使用最后一个正常区间的 idx（如果有），否则使用 0
        if (!src_out_items.empty()) {
            // 找到最后一个正常区间的 idx（排除 0-65535 区间）
            int last_normal_idx = -1;
            for (auto it = src_out_items.rbegin(); it != src_out_items.rend(); ++it) {
                if (!(it->src_lo == 0 && it->src_hi == 65535)) {
                    if (!it->idx_list.empty()) {
                        last_normal_idx = it->idx_list[0];
                        break;
                    }
                }
            }
            if (last_normal_idx >= 0) {
                full_range_copy.idx_list = {last_normal_idx};
            } else {
                full_range_copy.idx_list = {0};
            }
        } else {
            // 如果没有正常区间，使用 0
            full_range_copy.idx_list = {0};
        }
        src_out_items.push_back(std::move(full_range_copy));
    }
}


void Handle_Port_Hiding_Problem(std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& mateinfo,
                                 const std::vector<PortRule>& port_table)
{
    // 1) 按 G-ID1 分桶
    std::map<int, std::vector<MergedItem*>> gid_buckets;
    for (auto& [key, item] : mateinfo) {
        for (int gid : item.group_ids) {
            gid_buckets[gid].push_back(&item);
        }
    }

    // 2) 新的 metainfo
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem> new_mateinfo;

    // 3) 全局 idx 计数器：
    //    - 整个 meta_merged 中的 idx_list 全局唯一、单调递增
    //    - 同一 G-ID 内，相同 SRC 区间的所有 DST 段共享同一个 idx
    //    - 同一 G-ID 内的 0–65535 区间复用该 G-ID 内"最后一个正常 SRC 区间"的 idx
    int global_next_idx = 0;

    for (auto& [gid, items] : gid_buckets) {
        std::vector<MergedItem> src_split_items;

        // 3.1 先调用 SRC 拆分，获得局部的 src_split_items（带有局部 idx）
        int local_next_idx = 0;
        Split_SrcPort_Per_GID(gid, items, src_split_items, local_next_idx, port_table);

        // 3.2 统计当前 G-ID 内所有出现过的 (src_lo, src_hi)，分别分配全局 idx
        //     注意：这里不再使用局部 idx 的数值含义，只用它来区分不同 SRC 段。
        //     key: (src_lo, src_hi)  -> global_idx
        std::map<std::pair<int,int>, int> src2global_idx;
        int last_normal_idx = -1;
        int first_normal_idx = -1;  // 用于 DST=0-65535 的条目（优先级最低）

        // 先为所有"正常 SRC 区间（非 0–65535）"分配全局 idx
        for (auto& item : src_split_items) {
            bool is_full_src = (item.src_lo == 0 && item.src_hi == 65535);
            if (is_full_src)
                continue;

            std::pair<int,int> s_key{item.src_lo, item.src_hi};
            auto it = src2global_idx.find(s_key);
            if (it == src2global_idx.end()) {
                int gidx = global_next_idx++;
                it = src2global_idx.emplace(s_key, gidx).first;
            }

            item.idx_list = {it->second};
            if (it->second > last_normal_idx)
                last_normal_idx = it->second;
            if (first_normal_idx == -1)
                first_normal_idx = it->second;
        }

        // ★ 修复：为 SRC=0-65535 的条目分配 idx
        // 规则：
        // 1. SRC=0-65535 且 DST!=0-65535 的条目：使用统一的 idx（分配一个新的全局 idx，确保所有这样的条目共享同一个 idx）
        // 2. SRC=0-65535 且 DST=0-65535 的条目：也使用相同的 idx（与其他 SRC=0-65535 条目相同），但优先级最低（在输出时排在最后）
        int wildcard_src_idx = -1;  // SRC=0-65535 的统一 idx（包括 DST=0-65535 的条目）
        
        // 先处理 SRC=0-65535 且 DST!=0-65535 的条目
        for (auto& item : src_split_items) {
            bool is_full_src = (item.src_lo == 0 && item.src_hi == 65535);
            bool is_full_dst = (item.dst_lo == 0 && item.dst_hi == 65535);
            if (!is_full_src || is_full_dst)
                continue;
            
            // 为第一个 SRC=0-65535 且 DST!=0-65535 的条目分配一个新的统一 idx
            if (wildcard_src_idx == -1) {
                // 分配一个新的全局 idx，确保所有 SRC=0-65535 的条目（包括 DST=0-65535）共享同一个 idx
                wildcard_src_idx = global_next_idx++;
            }
            item.idx_list = {wildcard_src_idx};
        }
        
        // 再处理 SRC=0-65535 且 DST=0-65535 的条目（使用相同的 idx，但优先级最低）
        for (auto& item : src_split_items) {
            bool is_full_src = (item.src_lo == 0 && item.src_hi == 65535);
            bool is_full_dst = (item.dst_lo == 0 && item.dst_hi == 65535);
            if (!is_full_src || !is_full_dst)
                continue;
            
            // 使用与其他 SRC=0-65535 条目相同的 idx
            if (wildcard_src_idx == -1) {
                // 如果没有其他 SRC=0-65535 条目，分配一个新的 idx
                wildcard_src_idx = global_next_idx++;
            }
            item.idx_list = {wildcard_src_idx};
        }

        // 3.3 将当前 G-ID 处理后的所有条目写入 new_mateinfo
        //     确保优先级顺序：正常范围 > 长范围 DST（如 1025-65535）> 完全通配符 DST（0-65535）
        std::vector<MergedItem> sorted_items = src_split_items;
        std::sort(sorted_items.begin(), sorted_items.end(),
            [](const MergedItem& a, const MergedItem& b) {
                // 优先级顺序：正常范围 > 长范围 DST > 完全通配符 DST（0-65535）
                bool a_is_full_dst = (a.dst_lo == 0 && a.dst_hi == 65535);
                bool b_is_full_dst = (b.dst_lo == 0 && b.dst_hi == 65535);
                bool a_is_long_range = is_long_range_dst(a.dst_lo, a.dst_hi);
                bool b_is_long_range = is_long_range_dst(b.dst_lo, b.dst_hi);
                
                // 如果一个是完全通配符，另一个不是，完全通配符排在后面
                if (a_is_full_dst != b_is_full_dst) {
                    return !a_is_full_dst;  // DST=0-65535 的排在后面
                }
                
                // 如果都不是完全通配符，但一个是长范围，另一个不是，长范围排在后面
                if (!a_is_full_dst && !b_is_full_dst) {
                    if (a_is_long_range != b_is_long_range) {
                        return !a_is_long_range;  // 长范围排在后面
                    }
                    // 如果都是长范围，按照范围长度从小到大排序（范围更短的排在前面）
                    if (a_is_long_range && b_is_long_range) {
                        int a_range_len = a.dst_hi - a.dst_lo + 1;
                        int b_range_len = b.dst_hi - b.dst_lo + 1;
                        if (a_range_len != b_range_len) {
                            return a_range_len < b_range_len;  // 范围更短的排在前面
                        }
                    }
                }
                
                // 如果都是或都不是长范围/完全通配符，按原来的顺序（src_lo, src_hi, dst_lo, dst_hi）
                if (a.src_lo != b.src_lo) return a.src_lo < b.src_lo;
                if (a.src_hi != b.src_hi) return a.src_hi < b.src_hi;
                if (a.dst_lo != b.dst_lo) return a.dst_lo < b.dst_lo;
                return a.dst_hi < b.dst_hi;
            });
        
        for (auto& item : sorted_items) {
            auto key = std::make_tuple(item.group_ids, item.src_lo, item.src_hi,
                                       item.dst_lo, item.dst_hi);
            new_mateinfo[key] = item;
        }
    }

    // 4) 更新 mateinfo
    mateinfo = std::move(new_mateinfo);
}

void bulid_coverset_for_cell(vector<IntersectionCell>& intersections,
        vector<IntersectionCell>& Rmax_intersections,
        vector<IPRule>& merged_ip_table)
{
    auto build_for_cells = [&](vector<IntersectionCell>& cells){
        for (auto& cell : cells){
            cell.cover_set.clear();

            for (size_t i = 0; i < merged_ip_table.size(); ++i) {
                const auto& rule = merged_ip_table[i];
                // 1) proto 必须一致
                if (rule.proto != cell.proto)
                    continue;
                
                // 2) 检查规则是否被 cell 覆盖（即规则的 IP 范围在 cell 的 IP 范围内）
                // cell 覆盖 rule：cell.src_lo <= rule.src_ip_lo && rule.src_ip_hi <= cell.src_hi
                // cell 覆盖 rule：cell.dst_lo <= rule.dst_ip_lo && rule.dst_ip_hi <= cell.dst_hi
                if (cell.src_lo > rule.src_ip_lo || rule.src_ip_hi > cell.src_hi)
                    continue;

                // 3) dst 被 cell 覆盖
                if (cell.dst_lo > rule.dst_ip_lo || rule.dst_ip_hi > cell.dst_hi)
                    continue;
                
                cell.cover_set.push_back(i);
            }       
        }
    };

    build_for_cells(intersections);
    build_for_cells(Rmax_intersections);
}

void load_and_create_IP_table(vector<IPRule>& ip_table,
    vector<PortRule>& port_table, 
    vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem>& mateinfo)
{
    //1) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    cout << "[Main] Merged IP rules = " << merged_ip_table.size() << endl;

    //2) find Rmax for merged_ip_table
    vector<Rmax_IPRule> Rmax_merged_ip_table;
    vector<Rmax_IPRule> RO_merged_ip_table;
    vector<IntersectionCell> intersections;
    vector<IntersectionCell> Rmax_intersections;

    find_Rmax_for_merged_ip_table(merged_ip_table, Rmax_merged_ip_table);

    //2.5) Create Rmax_intersection_cells
    Search_Rmax_Intersection_per_proto(Rmax_merged_ip_table, Rmax_intersections);
    
    //2.6) Reorder Rmax table and get index mapping
    std::unordered_map<size_t, size_t> old_to_new_idx;
    Reorder_merged_ip_table(Rmax_merged_ip_table, RO_merged_ip_table, old_to_new_idx);
    
    //2.7) Update rmax_id in Rmax_intersections to use new indices
    for (auto& cell : Rmax_intersections) {
        if (cell.rmax_id != SIZE_MAX) {
            auto it = old_to_new_idx.find(cell.rmax_id);
            if (it != old_to_new_idx.end()) {
                cell.rmax_id = it->second;
            }
        }
    }
    
    //3) per-protocol elementary intervals (half-open endpoints)
    map<uint8_t, vector<uint32_t>> src_intervals_per_proto;
    map<uint8_t, vector<uint32_t>> dst_intervals_per_proto;
    build_elementary_intervals_per_proto(merged_ip_table,
        src_intervals_per_proto, dst_intervals_per_proto);
        
    //4) find intersection cells (per-proto)
    vector<size_t> rmax_rule_ids;
    find_intersections_per_proto(merged_ip_table, src_intervals_per_proto, 
        dst_intervals_per_proto, intersections, rmax_rule_ids);

    //5) Update rmax_id in intersections to use new indices
    // Note: intersections.rmax_id is merged_ip_table index, which equals Rmax_merged_ip_table index
    // We need to map from Rmax_merged_ip_table index to RO_merged_ip_table index
    for (auto& cell : intersections) {
        if (cell.rmax_id != SIZE_MAX) {
            auto it = old_to_new_idx.find(cell.rmax_id);
            if (it != old_to_new_idx.end()) {
                cell.rmax_id = it->second;
            }
        }
    }

    //6) merge intersection cells + merged IP table into final table
    vector<FinalIPRule> final_ip_table;
    merge_cells_and_ip_table(RO_merged_ip_table, intersections, Rmax_intersections, final_ip_table);    

    bulid_coverset_for_cell(intersections, Rmax_intersections, merged_ip_table);
    //7) transfer rule into mask type
    Create_Metainfo_for_port(port_table, merged_ip_table, intersections, Rmax_intersections, final_ip_table, RO_merged_ip_table, old_to_new_idx, mateinfo);
    
    //8) Handling Port Hiding Problem Within the Same G-ID
    Handle_Port_Hiding_Problem(mateinfo, port_table);

    Write_Metainfo_to_File(mateinfo);
    //9) write final ip table into file
    write_final_table_in_cidr(final_ip_table, "src/output/final_ip_table_cidr.txt");
}


#ifdef COMPILE_AS_STANDALONE_MAIN
int main(int argc, char **argv)  // accept optional path argument
{
    return 0;
}
#endif
