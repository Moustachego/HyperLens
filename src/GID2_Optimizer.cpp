/** *************************************************************/
// -------------------GID2 Encoding Optimizer--------------------
//
// This file implements GID2 wildcard compression for DST TCAM table.
// It reads DST_TCAM_Table.txt, groups entries by (DstPort, Action),
// then compresses GID2 values using binary Trie merging.
//
// Algorithm:
// 1. Parse DST TCAM entries: (GID2, DstPort, Action)
// 2. Group by (DstPort, Action) -> collect GID2 set
// 3. For each group, build binary Trie of GID2 values
// 4. Bottom-up merge: if both children exist, merge to wildcard
// 5. Output minimized wildcard patterns
//
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2026-02-02
/************************************************************* */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <memory>

#include "GID2_Optimizer.hpp"

using namespace std;

// ==================== Data Structures ====================

struct DST_TCAM_Entry {
    int gid2;
    string dst_port;    // 16-bit binary string (may contain wildcards)
    string action;
};

// Trie Node for binary encoding
struct TrieNode {
    shared_ptr<TrieNode> children[2];  // 0 and 1
    bool is_leaf = false;              // marks end of a GID2 value

    TrieNode() {
        children[0] = nullptr;
        children[1] = nullptr;
    }
};

// ==================== Global Variables ====================

int g_max_gid2 = 0;
int g_num_bits = 0;

// ==================== Helper Functions ====================

// Convert integer to binary string with specified width
string int_to_binary(int value, int bits) {
    string result(bits, '0');
    for (int i = bits - 1; i >= 0 && value > 0; i--) {
        result[i] = (value & 1) ? '1' : '0';
        value >>= 1;
    }
    return result;
}

// Calculate required bits for encoding
int calculate_bits(int max_value) {
    if (max_value <= 1) return 1;
    return (int)ceil(log2(max_value + 1));
}

// ==================== Trie Operations ====================

class GID2Trie {
private:
    shared_ptr<TrieNode> root;
    int num_bits;

public:
    GID2Trie(int bits) : num_bits(bits) {
        root = make_shared<TrieNode>();
    }

    // Insert a GID2 value into the Trie
    void insert(int gid2) {
        string binary = int_to_binary(gid2, num_bits);
        auto current = root;

        for (char c : binary) {
            int idx = c - '0';
            if (!current->children[idx]) {
                current->children[idx] = make_shared<TrieNode>();
            }
            current = current->children[idx];
        }
        current->is_leaf = true;
    }

    // Generate minimized wildcard patterns
    vector<string> generate_wildcards() {
        vector<string> result;
        string prefix;
        generate_wildcards_recursive(root, prefix, result);
        return result;
    }

private:
    // Check if subtree is complete (all possible values exist)
    // Returns: 0 = empty, 1 = partial, 2 = complete
    int subtree_status(shared_ptr<TrieNode> node, int depth) {
        if (!node) return 0;

        // At leaf level
        if (depth == num_bits) {
            return node->is_leaf ? 2 : 0;
        }

        int left_status = subtree_status(node->children[0], depth + 1);
        int right_status = subtree_status(node->children[1], depth + 1);

        // Both complete -> this subtree is complete
        if (left_status == 2 && right_status == 2) {
            return 2;
        }
        // Both empty -> empty
        if (left_status == 0 && right_status == 0) {
            return 0;
        }
        // Otherwise partial
        return 1;
    }

    // Recursive wildcard generation with bottom-up merging
    void generate_wildcards_recursive(shared_ptr<TrieNode> node,
                                       string& prefix,
                                       vector<string>& result) {
        if (!node) return;

        int remaining = num_bits - prefix.size();

        // At leaf level
        if (remaining == 0) {
            if (node->is_leaf) {
                result.push_back(prefix);
            }
            return;
        }

        // Check if current subtree can be fully wildcarded
        int status = subtree_status(node, prefix.size());

        if (status == 2) {
            // Complete subtree -> output all wildcards
            string wildcard = prefix + string(remaining, '*');
            result.push_back(wildcard);
            return;
        }

        if (status == 0) {
            // Empty subtree -> nothing to output
            return;
        }

        // Partial subtree -> try to merge children or recurse
        bool left_exists = (node->children[0] != nullptr);
        bool right_exists = (node->children[1] != nullptr);

        int left_status = left_exists ? subtree_status(node->children[0], prefix.size() + 1) : 0;
        int right_status = right_exists ? subtree_status(node->children[1], prefix.size() + 1) : 0;

        // If both children are complete, merge them
        if (left_status == 2 && right_status == 2) {
            string wildcard = prefix + "*" + string(remaining - 1, '*');
            result.push_back(wildcard);
            return;
        }

        // Otherwise, recurse into children
        if (left_exists) {
            prefix.push_back('0');
            generate_wildcards_recursive(node->children[0], prefix, result);
            prefix.pop_back();
        }

        if (right_exists) {
            prefix.push_back('1');
            generate_wildcards_recursive(node->children[1], prefix, result);
            prefix.pop_back();
        }
    }
};

// ==================== File I/O ====================

vector<DST_TCAM_Entry> load_dst_tcam_table(const string& filename) {
    vector<DST_TCAM_Entry> entries;
    ifstream file(filename);

    if (!file.is_open()) {
        cerr << "[ERROR] Cannot open file: " << filename << endl;
        return entries;
    }

    string line;
    int line_num = 0;

    while (getline(file, line)) {
        line_num++;

        // Skip header line
        if (line_num == 1 && line.find("GroupID2") != string::npos) {
            continue;
        }

        // Skip empty lines
        if (line.empty() || line.find_first_not_of(" \t\r\n") == string::npos) {
            continue;
        }

        istringstream iss(line);
        DST_TCAM_Entry entry;

        if (iss >> entry.gid2 >> entry.dst_port >> entry.action) {
            entries.push_back(entry);
            g_max_gid2 = max(g_max_gid2, entry.gid2);
        }
    }

    file.close();
    return entries;
}

void save_optimized_table(const string& filename,
                          const vector<tuple<string, string, string>>& optimized_entries) {
    ofstream file(filename);

    if (!file.is_open()) {
        cerr << "[ERROR] Cannot create output file: " << filename << endl;
        return;
    }

    // Write header
    file << left << setw(20) << "GID2_Wildcard"
         << setw(20) << "DstPort"
         << "Action" << endl;

    // Write entries
    for (const auto& entry : optimized_entries) {
        file << left << setw(20) << get<0>(entry)  // GID2 wildcard
             << setw(20) << get<1>(entry)          // DstPort
             << get<2>(entry) << endl;             // Action
    }

    file.close();
}

// ==================== Main Optimization Logic ====================

size_t run_gid2_optimizer(const string& input_file, const string& output_file) {
    // 重置全局状态（支持多次调用）
    g_max_gid2 = 0;
    g_num_bits = 0;

    cout << "[STEP 5] GID2 Encoding Optimizer" << endl;

    // Step 1: Load DST TCAM table
    vector<DST_TCAM_Entry> entries = load_dst_tcam_table(input_file);

    if (entries.empty()) {
        cerr << "[ERROR] GID2 Optimizer: No entries loaded from " << input_file << endl;
        return 0;
    }

    size_t original_count = entries.size();

    // Calculate bits needed for GID2 encoding
    g_num_bits = calculate_bits(g_max_gid2);

    // Step 2: Group by (DstPort, Action)
    map<pair<string, string>, set<int>> groups;

    for (const auto& entry : entries) {
        groups[{entry.dst_port, entry.action}].insert(entry.gid2);
    }

    // Step 3-5: For each group, build Trie and generate wildcards
    vector<tuple<string, string, string>> optimized_entries;

    for (const auto& group : groups) {
        const string& dst_port = group.first.first;
        const string& action = group.first.second;
        const set<int>& gid2_set = group.second;

        // Build Trie for this group's GID2 values
        GID2Trie trie(g_num_bits);
        for (int gid2 : gid2_set) {
            trie.insert(gid2);
        }

        // Generate wildcard patterns
        vector<string> wildcards = trie.generate_wildcards();

        // Add to optimized entries
        for (const string& wc : wildcards) {
            optimized_entries.push_back({wc, dst_port, action});
        }
    }

    // Step 6: Save optimized table
    save_optimized_table(output_file, optimized_entries);

    // Print summary
    cout << "         DST TCAM: " << original_count << " -> " << optimized_entries.size()
         << " entries (" << fixed << setprecision(1)
         << (1.0 - (double)optimized_entries.size() / original_count) * 100
         << "% reduction, GID2 " << g_num_bits << "-bit encoding)" << endl;

    return optimized_entries.size();
}

// ★ 独立运行入口（仅在单独编译时生效）
// 编译: g++-11 -std=c++17 src/GID2_Optimizer.cpp -o src/GID2_Optimizer
#ifndef HYPERLENS_MAIN
int main(int argc, char** argv) {
    string in  = (argc >= 2) ? argv[1] : "src/output/DST_TCAM_Table.txt";
    string out = (argc >= 3) ? argv[2] : "src/output/DST_TCAM_Table_Optimized.txt";
    size_t result = run_gid2_optimizer(in, out);
    return (result > 0) ? 0 : 1;
}
#endif
