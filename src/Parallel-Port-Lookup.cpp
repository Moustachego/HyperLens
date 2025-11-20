/** *************************************************************/
// @Name: Parallel Port Lookup.cpp
// @Function: Handle parallel port lookup for IP rules
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-11-16
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
#include "input.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"
#include "Parallel-Port-Lookup.hpp"

using namespace std;


static const size_t MAX_BLOCKS_ALLOWED = 3000000;    // 总 blocks 上限（防止 OOM），可调 这有什么作用？
static const uint32_t MAX_SINGLE_RANGE = 1u << 20; 


// 为单个 block 生成 32-bit 位图，严格按照 block_start 计算偏移
std::bitset<32> generate_32bit_bitmap(uint32_t block_start, uint32_t L, uint32_t H)
{
    std::bitset<32> bitmap;
    uint32_t start = std::max(block_start, L);
    uint32_t end   = std::min(block_start + 31, H);
    for (uint32_t p = start; p <= end; ++p) {
        bitmap.set(p - block_start);  // bitmap 内的位置 = 端口 - block_start
    }
    return bitmap;
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
    vector<MergedItem> full_range_items;   // 0-65535 范围的 item
};


SplitResult split_port_range_into_blocks(const vector<MergedItem> &meta_src)
{
    SplitResult result;
    size_t total_blocks = 0;

    for (const auto &item : meta_src)
    {
        if (item.group_ids.empty()) continue;

        uint32_t L = item.src_lo;
        uint32_t H = item.src_hi;
        if (L > H) continue;

        uint64_t range_len = (uint64_t)H - (uint64_t)L + 1u;
        if (range_len > MAX_SINGLE_RANGE) continue;

        uint32_t group_id = item.group_ids[0];

        // -------- 特殊处理：全端口 0-65535 --------
        if (L == 0 && H == 65535) {
            result.full_range_items.push_back(item); // 保存全端口 item
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
            bm.block_idx = block_idx;
            bm.SP = SP;
            bm.start = block_start;   // 记录真实起始端口
            bm.end   = block_end;     // 记录真实结束端口
            bm.assigned = false;

            // -------- 判断是否可以用单一 prefix --------
            uint32_t block_len = block_end - block_start + 1;
            bool can_use_prefix = is_power_of_two(block_len) && (block_start % block_len == 0);

            if (can_use_prefix) {
                bm.can_use_prefix = true;
                bm.bin_prefix = compute_bin_prefix(block_start, block_end);
            } else {
                bm.can_use_prefix = false;
                bm.bitmap = generate_32bit_bitmap(block_start, block_start, block_end);
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

    cerr << "[DBG] split_port_range_into_blocks produced blocks.size() = "
         << result.blocks.size()
         << ", full_range_items.size() = "
         << result.full_range_items.size() << "\n";

    return result;
}


vector<MergedItem> convert_mateifno_to_vector(
    const map<std::tuple<std::vector<int>, int, int>, MergedItem> &mateifno)
{
    vector<MergedItem> result;
    result.reserve(mateifno.size()); // small, keep as is
    for (const auto &kv : mateifno)
        result.push_back(kv.second);
    return result;
}

void fill_full_range_items_to_src_tcam(
    const std::vector<MergedItem>& full_range_items,
    std::vector<SRC_TCAM_Table>& src_tcam_table)
{
    for (const auto& item : full_range_items)
    {
        if (item.group_ids.empty()) {
            std::cerr << "[WARN] MergedItem has empty group_ids, skipping.\n";
            continue;
        }

        // 假设全端口范围 0-65535
        if (item.src_lo == 0 && item.src_hi == 65535)
        {
            SRC_TCAM_Table entry;
            entry.GroupID1 = static_cast<uint16_t>(item.group_ids[0]);
            entry.src_port_value = 0;    // 基准端口
            entry.src_port_mask  = 0x0000; // 全端口通配
            entry.GroupID2 = entry.GroupID1; // 同 GroupID
            entry.bin_prefix = std::string(16, '*');

            src_tcam_table.push_back(std::move(entry));
        }
        else
        {
            std::cerr << "[INFO] MergedItem is not full range, skipping: "
                      << item.src_lo << "-" << item.src_hi << "\n";
        }
    }

    std::cerr << "[INFO] fill_full_range_items_to_src_tcam produced "
              << src_tcam_table.size() << " entries.\n";
}


void merge_prefix_blocks(std::vector<BlockMeta>& blocks) {  //need to be checked
    // 按 group_id 和 src_lo 排序，保持顺序
    std::sort(blocks.begin(), blocks.end(), [](const BlockMeta &a, const BlockMeta &b) {
        if (a.group_id != b.group_id) return a.group_id < b.group_id;
        return a.start < b.end;  // 用实际端口顺序
    });

    size_t i = 0;
    while (i < blocks.size()) {
        // 只对 can_use_prefix=true 的 block 尝试合并
        if (!blocks[i].can_use_prefix) {
            i++;
            continue;
        }

        uint32_t merge_start = blocks[i].start;
        uint32_t merge_end = blocks[i].end;
        std::string merge_prefix = blocks[i].bin_prefix;
        size_t j = i + 1;

        // 尝试合并后续连续 block
        while (j < blocks.size() &&
               blocks[j].group_id == blocks[i].group_id &&
               blocks[j].can_use_prefix) {
            
            uint32_t candidate_start = merge_start;
            uint32_t candidate_end = blocks[j].end;

            // 计算合并后的公共前缀
            std::string candidate_prefix = compute_bin_prefix(candidate_start, candidate_end);

            // 判断合并后的 prefix 是否覆盖完整连续范围
            uint32_t mask_len = 0;
            for (char c : candidate_prefix) if (c != '*') mask_len++;

            uint32_t prefix_range_len = 1u << (16 - mask_len);
            // prefix_range_len 必须对齐 candidate_start，否则不能合并
            if (candidate_start % prefix_range_len != 0) break;

            // 合并成功，更新 merge_end 和 merge_prefix
            merge_end = candidate_end;
            merge_prefix = candidate_prefix;
            j++;
        }

        // 更新第 i 个 block
        blocks[i].start = merge_start;
        blocks[i].end = merge_end;
        blocks[i].bin_prefix = merge_prefix;
        blocks[i].can_use_prefix = true;
        
        blocks[i].assigned = true;

        // 删除已经被合并掉的 block
        if (j > i + 1) {
            blocks.erase(blocks.begin() + i + 1, blocks.begin() + j);
        }

        i++;
    }
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
        for (int i = 31; i >= 0; --i) s += b[i] ? '1' : '0';
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
        if (bm.can_use_prefix && bm.assigned) {
            // 分配到 TCAM
            SRC_TCAM_Table entry{};
            entry.GroupID1 = static_cast<uint16_t>(bm.group_id);
            entry.GroupID2 = entry.GroupID1;
            entry.bin_prefix = bm.bin_prefix;
            src_tcam_table.push_back(std::move(entry));
        } else {
            // 分配到 SRAM
            SRC_SRAM_Table entry;
            entry.GroupID1 = static_cast<uint16_t>(bm.group_id);
            entry.GroupID2 = entry.GroupID1;
            entry.SP_Quotient = static_cast<uint16_t>(bm.SP);

            entry.bitmap.clear();
            for (size_t k = 0; k < 32; ++k) {
                if (bm.bitmap.test(k)) entry.bitmap.push_back(k);
            }
            src_sram_table.push_back(std::move(entry));
        }
    }

    output_sram_tcam_tables(src_tcam_table, src_sram_table);
}

//-------------------- Step 9: Main function to build SRC port tables --------------------
void create_Table_for_SRC_port(
    const vector<PortRule>& port_table,
    const vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno
){
    auto meta_src_list = convert_mateifno_to_vector(mateifno);

    auto split_result = split_port_range_into_blocks(meta_src_list);
    auto &blocks = split_result.blocks;
    auto &full_range_items = split_result.full_range_items;

    std::vector<SRC_SRAM_Table> src_sram_table;
    std::vector<SRC_TCAM_Table> src_tcam_table;

    fill_full_range_items_to_src_tcam(full_range_items, src_tcam_table);

    merge_prefix_blocks(blocks);

    assign_blocks_to_sram_tcam(blocks, src_sram_table, src_tcam_table);

}

void laod_and_create_IP_table(vector<IPRule>& ip_table,
    vector<PortRule>& port_table, 
    vector<IPRule>& merged_ip_table,
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem>& mateifno)
{
    // 2) merge identical IP entries
    merge_same_ip_entry(ip_table, merged_ip_table);

    cout << "[Main] Merged IP rules = " << merged_ip_table.size() << endl;

    // 3.5) find Rmax for merged_ip_table
    vector<Rmax_IPRule> Rmax_merged_ip_table;
    find_Rmax_for_merged_ip_table(merged_ip_table, Rmax_merged_ip_table);

    // 3) per-protocol elementary intervals (half-open endpoints)
    map<uint8_t, vector<uint32_t>> src_intervals_per_proto;
    map<uint8_t, vector<uint32_t>> dst_intervals_per_proto;
    build_elementary_intervals_per_proto(merged_ip_table,
        src_intervals_per_proto, dst_intervals_per_proto);

    // 4) find intersection cells (per-proto)
    vector<IntersectionCell> intersections;
    vector<size_t> rmax_rule_ids;
    find_intersections_per_proto(merged_ip_table, src_intervals_per_proto, 
        dst_intervals_per_proto, intersections, rmax_rule_ids);

    vector<IPRule> extra_rules;
    extract_and_split_cells(merged_ip_table, intersections, extra_rules);
    cout << "[INFO] Extra rules (range only, no CIDR): " << extra_rules.size() << endl;

    // 7) merge intersection cells + merged IP table into final table
    vector<FinalIPRule> final_ip_table;
    merge_cells_and_ip_table(Rmax_merged_ip_table, intersections, final_ip_table);    

    //8) transfer rule into mask type
    // export final IP table

    Create_Metainfo_for_SRC_port(port_table, merged_ip_table, intersections, final_ip_table, mateifno);
    write_final_table_in_cidr(final_ip_table, "final_ip_table_cidr.txt");
}

/*************************************************************
 * Step 5: main
 *************************************************************/
int main(int argc, char **argv)  // accept optional path argument
{
    string rules_path = "src/ACL_rules/test.rules";
    if (argc >= 2) rules_path = string(argv[1]);

    vector<Rule5D> rules;
    vector<IPRule> merged_ip_table;
    // attempt to load rules; load_rules_from_file will exit(1) on failure
    load_rules_from_file(rules_path, rules);

    // Optional: show a quick summary so user knows program progressed
    cout << "[Parallel-Port-Lookup] Loaded " << rules.size() << " rules from '" << rules_path << "'\n";

    // Example continuation: split rules and prepare merged ip table (non-mandatory)
    vector<IPRule> ip_table;
    vector<PortRule> port_table;
    std::map<std::tuple<std::vector<int>, int, int>, MergedItem> mateifno;

    split_rules(rules, ip_table, port_table);
    merge_same_ip_entry(ip_table, merged_ip_table);

    laod_and_create_IP_table(ip_table, port_table, merged_ip_table, mateifno);

    // make block for mateifno

    cout << "[Parallel-Port-Lookup] IP entries=" << ip_table.size()
         << ", Port entries=" << port_table.size()
         << ", Merged IP=" << merged_ip_table.size() << "\n";

    // Call the refactored function and capture results
    create_Table_for_SRC_port(port_table, merged_ip_table, mateifno);

    return 0;
}
