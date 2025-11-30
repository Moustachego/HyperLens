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


static const size_t MAX_BLOCKS_ALLOWED = 3000000;    // 总 blocks 上限（防止 OOM），可调 这有什么作用？
static const uint32_t MAX_SINGLE_RANGE = 1u << 20; 


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
            bm.src_item_idx = static_cast<uint32_t>(item_idx);
            bm.block_idx = block_idx;
            bm.SP = SP;
            bm.start = block_start;
            bm.end = block_end;
            bm.assigned = false;
            bm.single_value = (block_start == block_end);

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

    // debug prints removed

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
            // ACTION: 如果有多个，取第一个作为默认动作
            entry.Action = item.Action.empty() ? 0 : static_cast<uint16_t>(item.Action[0]);

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

                // group_id2 在组内相同，若出现不同则置 0（不过排序保证同组相同）
                M.group_id2 = (A.group_id2 == B.group_id2) ? A.group_id2 : 0;

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
            entry.Action = bm.Action.empty() ? 0 : static_cast<uint16_t>(bm.Action[0]);
            dst_tcam_table.push_back(std::move(entry));
        } else {
            DST_SRAM_Table entry;
            entry.GroupID2 = static_cast<uint16_t>(bm.group_id2);
            entry.SP_Quotient = static_cast<uint16_t>(bm.SP);
            entry.Action = bm.Action.empty() ? 0 : static_cast<uint16_t>(bm.Action[0]);
            entry.bitmap.clear();
            for (size_t k = 0; k < 32; ++k) if (bm.bitmap.test(k)) entry.bitmap.push_back(k);
            dst_sram_table.push_back(std::move(entry));
        }
    }

    // 输出到文件
    std::sort(dst_tcam_table.begin(), dst_tcam_table.end(), [](const DST_TCAM_Table &a, const DST_TCAM_Table &b){
        return a.GroupID2 < b.GroupID2;
    });
    std::ofstream dtcam("DST_TCAM_Table.txt");
    dtcam << std::left << std::setw(12) << "GroupID2" << std::setw(20) << "DstPort" << std::setw(10) << "Action" << "\n";
    for (const auto &e : dst_tcam_table) {
        dtcam << std::left << std::setw(12) << e.GroupID2 << std::setw(20) << e.bin_prefix << std::setw(10) << e.Action << "\n";
    }
    dtcam.close();

    std::sort(dst_sram_table.begin(), dst_sram_table.end(), [](const DST_SRAM_Table &a, const DST_SRAM_Table &b){
        if (a.GroupID2 != b.GroupID2) return a.GroupID2 < b.GroupID2;
        return a.SP_Quotient < b.SP_Quotient;
    });
    std::ofstream dsram("DST_SRAM_Table.txt");
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
    std::sort(src_tcam_table.begin(), src_tcam_table.end(),
        [](const SRC_TCAM_Table &a, const SRC_TCAM_Table &b) {
            return a.GroupID1 < b.GroupID1;
        }
    );

    std::ofstream tcam_file("SRC_TCAM_Table.txt");
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
    std::sort(src_sram_table.begin(), src_sram_table.end(),
        [](const SRC_SRAM_Table &a, const SRC_SRAM_Table &b) {
            if (a.GroupID1 != b.GroupID1) return a.GroupID1 < b.GroupID1;
            return a.SP_Quotient < b.SP_Quotient;
        }
    );

    std::ofstream sram_file("SRC_SRAM_Table.txt");
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

    output_sram_tcam_tables(src_tcam_table, src_sram_table);
}

// 将 merged_output 格式的 mateifno 拆分为以 src 为主和以 dst 为主的两个列表
void split_mateinfo_into_src_dst(
    const std::map<std::tuple<std::vector<int>, int, int>, MergedItem> &mateifno,
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
std::vector<DST_Port_Item> build_dst_items_from_mate_dst_list(const std::vector<Mate_DST_LIST> &mate_dst) {
    std::vector<DST_Port_Item> dst_items;
    dst_items.reserve(mate_dst.size());
    for (const auto &d : mate_dst) {
        DST_Port_Item it;
        it.group_ids1 = d.group_ids;
        it.dst_lo = d.dst_lo;
        it.dst_hi = d.dst_hi;
        // Initialize Action from mate_dst.action
        it.Action.push_back(d.action);
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
    std::ofstream fout("src_items.txt");
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
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno
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

void laod_and_create_IP_table(vector<IPRule>& ip_table,
    vector<PortRule>& port_table, 
    vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno)
{
    //1) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    cout << "[Main] Merged IP rules = " << merged_ip_table.size() << endl;

    //2) find Rmax for merged_ip_table
    vector<Rmax_IPRule> Rmax_merged_ip_table;
    find_Rmax_for_merged_ip_table(merged_ip_table, Rmax_merged_ip_table);

    //3) per-protocol elementary intervals (half-open endpoints)
    map<uint8_t, vector<uint32_t>> src_intervals_per_proto;
    map<uint8_t, vector<uint32_t>> dst_intervals_per_proto;
    build_elementary_intervals_per_proto(merged_ip_table,
        src_intervals_per_proto, dst_intervals_per_proto);
        
    //4) find intersection cells (per-proto)
    vector<IntersectionCell> intersections;
    vector<size_t> rmax_rule_ids;
    find_intersections_per_proto(merged_ip_table, src_intervals_per_proto, 
        dst_intervals_per_proto, intersections, rmax_rule_ids);

    //5)Independent set partitioning
    vector<IPRule> extra_rules; // pass now , filled later
    extract_and_split_cells(merged_ip_table, intersections, extra_rules);
    cout << "[INFO] Extra rules (range only, no CIDR): " << extra_rules.size() << endl;

    //6) merge intersection cells + merged IP table into final table
    vector<FinalIPRule> final_ip_table;
    merge_cells_and_ip_table(Rmax_merged_ip_table, intersections, final_ip_table);    

    //7) transfer rule into mask type
    Create_Metainfo_for_port(port_table, merged_ip_table, intersections, final_ip_table, mateifno);
    
    //8) write final ip table into file
    write_final_table_in_cidr(final_ip_table, "final_ip_table_cidr.txt");
}


#ifdef COMPILE_AS_STANDALONE_MAIN
int main(int argc, char **argv)  // accept optional path argument
{
    return 0;
}
#endif
