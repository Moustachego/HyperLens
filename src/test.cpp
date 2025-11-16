#include <iostream>
#include <vector>
#include <string>
#include <bitset>
#include <cmath>
using namespace std;

vector<pair<uint32_t, int>> range_to_prefix(uint32_t lo, uint32_t hi) {
    vector<pair<uint32_t, int>> res;
    while (lo <= hi) {
        uint32_t max_size = lo & -lo;
        int max_len = 32 - __builtin_ctz(max_size);
        while (max_len > 0) {
            uint64_t block = 1ULL << (32 - max_len);
            if (lo + block - 1 > hi) max_len--;
            else break;
        }
        res.push_back({lo, max_len});
        lo += 1ULL << (32 - max_len);
    }
    return res;
}

string ip_to_string(uint32_t ip) {
    return to_string((ip >> 24) & 0xFF) + "." +
           to_string((ip >> 16) & 0xFF) + "." +
           to_string((ip >> 8) & 0xFF) + "." +
           to_string(ip & 0xFF);
}

int main() {
    cout << "Program started!\n";
    uint32_t lo = (192<<24)|(168<<16)|(1<<8)|0;   // 192.168.1.0
    uint32_t hi = (192<<24)|(168<<16)|(1<<8)|63;  // 192.168.1.63

    auto prefixes = range_to_prefix(lo, hi);
    cout << "补充规则 CIDR 为:\n";
    for (auto &p : prefixes)
        cout << "  " << ip_to_string(p.first) << "/" << p.second << "\n";

    cout << "Done.\n";
    return 0;
}
