/** *************************************************************/
// -------------------Main Entry Point for HyperLens--------------------
// 
// This file serves as the unified main entry point for the HyperLens project.
// It orchestrates the loading of ACL rules and the generation of TCAM/SRAM tables
// for both SRC and DST port lookups.
// @Author: weijzh (weijzh@pcl.ac.cn)
// @Created: 2025-10-30
/************************************************************* */

#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <tuple>
#include "Loader.hpp"
#include "Dependent-Set-Prefix-Lookup.hpp"
#include "Parallel-Port-Lookup.hpp"

using std::cout;
using std::cerr;
using std::string;
using std::vector;
using std::endl;

/*
 * Main entry point for HyperLens
 * 
 * Accepts an optional command-line argument for the rules file path.
 * Default: "src/ACL_rules/test_port.rules"
 * 
 * Workflow:
 * 1. Load rules from file
 * 2. Split into IP and Port tables
 * 3. Merge identical IP entries
 * 4. Create IP table metadata and port table lookups
 * 5. Generate TCAM/SRAM table outputs
 */

int main(int argc, char **argv)
{
    // Parse command-line arguments
    string rules_path = "src/ACL_rules/test.rules";
    if (argc >= 2) {
        rules_path = string(argv[1]);
    }

    cout << "===============================================================================\n";
    cout << "---------------------------------- HyperLens ----------------------------------\n";
    cout << "===============================================================================\n\n";

    // Step 1: Load rules from file
    cout << "[STEP 1] Loading rules from: " << rules_path << endl;
    vector<Rule5D> rules;
    try {
        load_rules_from_file(rules_path, rules);
    } catch (const std::exception &e) {
        cerr << "[ERROR] Failed to load rules: " << e.what() << endl;
        return 1;
    }

    cout << "[SUCCESS] Loaded " << rules.size() << " rules\n\n";

    // Step 2: Split rules into IP and Port tables
    cout << "[STEP 2] Splitting rules into IP and Port tables...\n";
    vector<IPRule> ip_table;
    vector<PortRule> port_table;
    split_rules(rules, ip_table, port_table);
    cout << "[SUCCESS] IP table: " << ip_table.size() << " entries, "
         << "Port table: " << port_table.size() << " entries\n\n";

    // Step 3: Create metadata and tables
    // (laod_and_create_IP_table internally handles IP merge, intersection detection, and metainfo generation)
    cout << "[STEP 3] Creating IP Table and port metadata...\n";
    vector<IPRule> merged_ip_table;
    std::map<std::tuple<std::vector<int>, int, int, int, int>, MergedItem> mateinfo;
    load_and_create_IP_table(ip_table, port_table, merged_ip_table, mateinfo);
    cout << "[SUCCESS] IP Table and metadata processing completed (Merged to " << merged_ip_table.size() << " unique IP entries)\n\n";

    // Step 4: Generate TCAM/SRAM tables for both SRC and DST
    cout << "[STEP 4] Generating TCAM/SRAM tables for port lookups...\n";
    create_Table_for_port(port_table, merged_ip_table, mateinfo);
    cout << "[SUCCESS] Port lookup tables generated\n\n";

    cout << "===============================================================================\n";
    cout << "HyperLens processing completed successfully!\n";
    cout << "Output files generated in src/output/:\n";
    cout << "  - SRC_TCAM_Table.txt\n";
    cout << "  - SRC_SRAM_Table.txt\n";
    cout << "  - DST_TCAM_Table.txt\n";
    cout << "  - DST_SRAM_Table.txt\n";
    cout << "  - final_ip_table_cidr.txt\n";
    cout << "  - meta_merged.txt\n";
    cout << "===============================================================================\n";

    return 0;
}
