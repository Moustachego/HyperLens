#!/usr/bin/env python3
"""
Self-inspection script for HyperLens verification
Step (1): Load test packets and bind them to original rules & actions
"""

import ipaddress
import sys
import os
import json
from datetime import datetime
from collections import Counter


class FailStage:
    IP = "IP"
    SRC_TCAM = "SRC_TCAM"
    SRC_SRAM = "SRC_SRAM"
    DST_TCAM = "DST_TCAM"
    DST_SRAM = "DST_SRAM"
    ACTION = "ACTION"

# ============================================================
# Basic utilities
# ============================================================

def ip_to_int(ip_str):
    return int(ipaddress.IPv4Address(ip_str))


def ip_in_network(ip_str, network):
    ip = ipaddress.IPv4Address(ip_str)
    return ip in network


# ============================================================
# Load final IP table (unchanged)
# ============================================================

def load_final_ip_table(filename):
    rules = []
    with open(filename, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines[1:], 0):
        parts = line.strip().split()
        if len(parts) >= 5:
            rule = {
                'index': i,
                'priority': int(parts[0]),
                'src_ip': parts[1],
                'dst_ip': parts[2],
                'protocol': int(parts[3]),
                'gids': parts[4]
            }

            rule['src_network'] = ipaddress.IPv4Network(
                rule['src_ip'] if '/' in rule['src_ip'] else rule['src_ip'] + '/32',
                strict=False
            )
            rule['dst_network'] = ipaddress.IPv4Network(
                rule['dst_ip'] if '/' in rule['dst_ip'] else rule['dst_ip'] + '/32',
                strict=False
            )

            rules.append(rule)

    return rules


# ============================================================
# STEP (1.1) Load test packets (packet, not rule)
# ============================================================

def load_test_packets(filename):
    packets = []

    with open(filename, 'r') as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue

            parts = line.strip().split()
            if len(parts) < 5:
                continue

            pkt = {
                # Packet fields
                'src_ip': parts[0],
                'dst_ip': parts[1],
                'src_port': int(parts[2]),
                'dst_port': int(parts[3]),
                'protocol': int(parts[4]),
                'packet_index': i,

                # Rule binding (STEP 1)
                'rule_index': None,          # Rk
                'expected_action': None,     # from *.rules

                # Placeholders for later steps
                'matched_gids': [],
                'src_group_id': None,
                'dst_group_id': None,
                'final_action': None,
                'fail_stage': None,
                'fail_reason': None

            }

            # Parse //Rk
            if len(parts) > 5 and parts[5].startswith('//R'):
                try:
                    pkt['rule_index'] = int(parts[5][3:])
                except ValueError:
                    pkt['rule_index'] = None

            packets.append(pkt)

    return packets


# ============================================================
# STEP (1.2) Load original rules and extract Action
# ============================================================

def load_rules_with_action(filename):
    """
    Load original rule set (*.rules) and extract action per rule.
    Assumes rule order == R0, R1, R2, ...
    """
    rule_actions = {}
    rule_idx = 0

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('@'):
                continue

            parts = line.split()
            action = parts[-1]   # e.g., 0x1000/0x1000
            rule_actions[rule_idx] = action
            rule_idx += 1

    return rule_actions


# ============================================================
# Matching (kept for later steps, unused now)
# ============================================================

def match_test_rule_against_final_table(test_rule, final_table):
    matches = []

    for final_rule in final_table:
        if (ip_in_network(test_rule['src_ip'], final_rule['src_network']) and
            ip_in_network(test_rule['dst_ip'], final_rule['dst_network']) and
            test_rule['protocol'] == final_rule['protocol']):
            matches.append(final_rule)

    matches.sort(key=lambda x: x['priority'])
    return matches

def match_packet_to_final_ip_table(pkt, final_table):
    """
    Match packet against final_ip_table using:
    SrcIP / DstIP / Protocol

    Returns:
        matched_gids (list) or None if no match
    """
    matches = []

    for rule in final_table:
        if (
            ip_in_network(pkt['src_ip'], rule['src_network']) and
            ip_in_network(pkt['dst_ip'], rule['dst_network']) and
            pkt['protocol'] == rule['protocol']
        ):
            matches.append(rule)

    if not matches:
        return None

    # lower priority value = higher priority
    matches.sort(key=lambda r: r['priority'])

    best_rule = matches[0]
    return parse_gids(best_rule['gids'])

# ============================================================
# GID parsing utility (STEP 2)
# ============================================================

def parse_gids(gid_str):
    """
    Parse GID field like:
      "5"      -> [5]
      "3,7"    -> [3, 7]
    """
    gids = []
    for g in gid_str.split(','):
        g = g.strip()
        if g:
            gids.append(int(g))
    return gids

# ============================================================
# SRC TCAM utilities (STEP 3)
# ============================================================

def port_to_bin(port, width=16):
    """Convert port number to fixed-width binary string"""
    return format(port, f'0{width}b')


def tcam_match(value_bin, pattern):
    """
    TCAM wildcard match:
    '0' / '1' must equal
    '*' matches anything
    """
    if len(value_bin) != len(pattern):
        return False

    for v, p in zip(value_bin, pattern):
        if p == '*':
            continue
        if v != p:
            return False
    return True

def load_src_tcam_table(filename):
    """
    Parse SRC_TCAM_Table.txt

    Expected columns:
    GroupID1 | SrcPort(pattern) | GroupID2
    """
    table = []

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('GroupID'):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            entry = {
                'group_id1': int(parts[0]),
                'pattern': parts[1],
                'group_id2': int(parts[2])
            }
            table.append(entry)

    return table


def src_tcam_lookup(pkt, src_tcam_table):
    if not pkt.get('matched_gids'):
        pkt['fail_stage'] = FailStage.SRC_TCAM
        pkt['fail_reason'] = "No matched_gids (GID1) available"
        return False

    src_port_bin = port_to_bin(pkt['src_port'])

    add_debug(pkt, FailStage.SRC_TCAM, {
        'src_port': pkt['src_port'],
        'src_port_bin': src_port_bin,
        'candidate_gid1': pkt['matched_gids']
    })

    for gid1 in pkt['matched_gids']:
        for rule in src_tcam_table:
            if rule['group_id1'] != gid1:
                continue

            if tcam_match(src_port_bin, rule['pattern']):
                pkt['src_group_id'] = rule['group_id2']
                add_debug(pkt, FailStage.SRC_TCAM, {
                    'hit': True,
                    'gid1': gid1,
                    'pattern': rule['pattern'],
                    'gid2': rule['group_id2']
                })
                return True

    add_debug(pkt, FailStage.SRC_TCAM, {
        'hit': False,
        'reason': 'TCAM miss'
    })
    return False



def load_src_sram_table(filename):
    """
    Parse SRC_SRAM_Table.txt

    Columns:
      GroupID1 | SP_Quotient | Bitmap32 | GroupID2
    """
    table = []

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('GroupID'):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            entry = {
                'group_id1': int(parts[0]),
                'quotient': int(parts[1]),
                'bitmap': parts[2],
                'group_id2': int(parts[3])
            }
            table.append(entry)

    return table

def src_sram_lookup(pkt, src_sram_table):
    if not pkt.get('matched_gids'):
        pkt['fail_stage'] = FailStage.SRC_SRAM
        pkt['fail_reason'] = "No matched_gids (GID1) available"
        return False

    port = pkt['src_port']
    quotient = port // 32
    remainder = port % 32

    add_debug(pkt, FailStage.SRC_SRAM, {
        'src_port': port,
        'quotient': quotient,
        'bit_index': remainder
    })

    for entry in src_sram_table:
        if entry['group_id1'] not in pkt['matched_gids']:
            continue
        if entry['quotient'] != quotient:
            continue

        bitmap = entry['bitmap']
        if len(bitmap) != 32:
            continue
        bit_pos = 31 - remainder
        bit_val = bitmap[bit_pos]

        add_debug(pkt, FailStage.SRC_SRAM, {
            'gid1': entry['group_id1'],
            'bitmap': bitmap,
            'checked_bit': bit_pos,
            'bit_value': bit_val
        })

        if bit_val == '1':
            pkt['src_group_id'] = entry['group_id2']
            return True

    pkt['fail_stage'] = FailStage.SRC_SRAM
    pkt['fail_reason'] = 'SRC TCAM + SRAM miss'
    return False



# ============================================================
# DST TCAM / SRAM utilities (STEP 4)
# ============================================================

def load_dst_tcam_table(filename):
    """
    Parse DST_TCAM_Table.txt

    Expected columns:
    GroupID2 | DstPort(pattern) | Action
    """
    table = []

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('GroupID'):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            entry = {
                'group_id2': int(parts[0]),
                'pattern': parts[1],
                'action': parts[2]
            }
            table.append(entry)

    return table


def load_dst_sram_table(filename):
    """
    Parse DST_SRAM_Table.txt

    Expected columns:
    GroupID2 | SP_Quotient | Bitmap32 | Action
    """
    table = []

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('GroupID'):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            entry = {
                'group_id2': int(parts[0]),
                'quotient': int(parts[1]),
                'bitmap': parts[2],
                'action': parts[3]
            }
            table.append(entry)

    return table

def dst_tcam_lookup(pkt, dst_tcam_table):
    gid2 = pkt.get('src_group_id')
    if gid2 is None:
        pkt['fail_stage'] = FailStage.DST_TCAM
        pkt['fail_reason'] = "No src_group_id (GID2) available"
        return False

    dst_port_bin = port_to_bin(pkt['dst_port'])

    add_debug(pkt, FailStage.DST_TCAM, {
        'gid2': gid2,
        'dst_port': pkt['dst_port'],
        'dst_port_bin': dst_port_bin
    })

    for rule in dst_tcam_table:
        if rule['group_id2'] != gid2:
            continue

        if tcam_match(dst_port_bin, rule['pattern']):
            # 直接使用从表中读取的 action 字符串，不需要转换
            pkt['resolved_action'] = rule['action']
            # 解析 value/mask 以便后续验证
            try:
                pkt['resolved_action_value'], pkt['resolved_action_mask'] = \
                    parse_action(rule['action'])
            except (ValueError, KeyError) as e:
                pkt['fail_stage'] = FailStage.ACTION
                pkt['fail_reason'] = f"Invalid action format: {rule['action']}, error: {e}"
                return False
            add_debug(pkt, FailStage.DST_TCAM, {
                'hit': True,
                'pattern': rule['pattern'],
                'action': rule['action']
            })
            return True

    add_debug(pkt, FailStage.DST_TCAM, {
        'hit': False,
        'reason': 'TCAM miss'
    })
    return False

def dst_sram_lookup(pkt, dst_sram_table):
    gid2 = pkt.get('src_group_id')
    if gid2 is None:
        pkt['fail_stage'] = FailStage.DST_SRAM
        pkt['fail_reason'] = "No src_group_id (GID2) available"
        return False

    port = pkt['dst_port']
    quotient = port // 32
    bit = port % 32

    add_debug(pkt, FailStage.DST_SRAM, {
        'gid2': gid2,
        'dst_port': port,
        'quotient': quotient,
        'bit_index': bit
    })

    for rule in dst_sram_table:
        if rule['group_id2'] != gid2:
            continue
        if rule['quotient'] != quotient:
            continue

        bitmap = rule['bitmap']
        if len(bitmap) != 32:
            continue
        pos = 31 - bit
        val = bitmap[pos]

        add_debug(pkt, FailStage.DST_SRAM, {
            'bitmap': bitmap,
            'checked_bit': pos,
            'bit_value': val
        })

        if val == '1':
            # 直接使用从表中读取的 action 字符串，不需要转换
            pkt['resolved_action'] = rule['action']
            # 解析 value/mask 以便后续验证
            try:
                pkt['resolved_action_value'], pkt['resolved_action_mask'] = \
                    parse_action(rule['action'])
            except (ValueError, KeyError) as e:
                pkt['fail_stage'] = FailStage.ACTION
                pkt['fail_reason'] = f"Invalid action format: {rule['action']}, error: {e}"
                return False
            return True

    pkt['fail_stage'] = FailStage.DST_SRAM
    pkt['fail_reason'] = "DST TCAM + SRAM miss"
    return False

# ============================================================
# STEP (5) Action Table
# ============================================================

def build_action_table_from_rules(rules_file):
    """
    Build ActionID -> Action mapping
    Assumption:
        ActionID == rule index (R0, R1, ...)
    """
    action_table = {}

    rule_idx = 0
    with open(rules_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith('@'):
                continue

            parts = line.split()
            action = parts[-1]
            action_table[rule_idx] = action
            rule_idx += 1

    return action_table

def resolve_action(pkt, action_table):
    """
    验证 action 是否已从 DST 表中解析
    现在 action 直接从 DST TCAM/SRAM 表中获取，不需要通过 action_table 查找
    """
    # action 应该已经在 dst_tcam_lookup 或 dst_sram_lookup 中设置
    if 'resolved_action' not in pkt:
        pkt['fail_stage'] = FailStage.ACTION
        pkt['fail_reason'] = "Missing resolved_action (should be set by DST lookup)"
        return False
    
    # action 已经解析，直接返回成功
    # resolved_action_value 和 resolved_action_mask 也应该已经设置
    return True



def add_debug(pkt, stage, info: dict):
    pkt.setdefault('debug_trace', []).append({
        'stage': stage,
        'info': info
    })


def parse_action(action_str):
    """
    Parse action like '0x0010/0xFFFF'
    Return (value:int, mask:int)
    """
    if '/' not in action_str:
        raise ValueError(f"Invalid action format: {action_str}")

    v, m = action_str.split('/')
    return int(v, 16), int(m, 16)


def dump_failed_packets(packets, log_file):
    log_file.write("\n" + "=" * 80 + "\n")
    log_file.write("FAILED PACKETS DETAIL TRACE\n")
    log_file.write("=" * 80 + "\n")

    fail_cnt = 0

    for i, pkt in enumerate(packets):
        if pkt.get('fail_stage') is None:
            continue

        fail_cnt += 1
        log_file.write(f"\n[FAIL #{fail_cnt}] Packet Index: {i}\n")
        log_file.write("-" * 60 + "\n")

        log_file.write(
            f"5-Tuple: "
            f"SRC={pkt['src_ip']}:{pkt['src_port']}  "
            f"DST={pkt['dst_ip']}:{pkt['dst_port']}  "
            f"PROTO={pkt['protocol']}\n"
        )

        log_file.write(f"Expected Action : {pkt.get('expected_action')}\n")
        log_file.write(f"Resolved Action : {pkt.get('resolved_action')}\n")
        log_file.write(f"Fail Stage      : {pkt.get('fail_stage')}\n")
        log_file.write(f"Fail Reason     : {pkt.get('fail_reason')}\n")

        # ★ 打印 debug trace（关键）
        if 'debug' in pkt:
            log_file.write("Debug Trace:\n")
            for stage, info in pkt['debug'].items():
                log_file.write(f"  [{stage}]\n")
                for k, v in info.items():
                    log_file.write(f"    {k}: {v}\n")

    if fail_cnt == 0:
        log_file.write("\nNo failed packets 🎉\n")


# ============================================================
# Main
# ============================================================

def main():
    base_path = os.path.join('src', 'output')
    ACL_path  = os.path.join('src', 'ACL_rules')

    testset_file = os.path.join(base_path, 'acl1_50k_16_0.5_c_testset.txt')
    rules_file   = os.path.join(ACL_path, 'acl1/acl1_50k_16_0.5_c.rules')

    final_ip_table_file = os.path.join(base_path, 'final_ip_table_cidr.txt')
    src_tcam_file = os.path.join(base_path, 'SRC_TCAM_Table.txt')
    src_sram_file = os.path.join(base_path, 'SRC_SRAM_Table.txt')
    dst_tcam_file = os.path.join(base_path, 'DST_TCAM_Table.txt')
    dst_sram_file = os.path.join(base_path, 'DST_SRAM_Table.txt')

    log_file_path = os.path.join(base_path, 'self_inspection_log.txt')

    log_file = open(log_file_path, 'w')
    log_file.write("HyperLens Self-Inspection Log (STEP 1–5)\n")
    log_file.write("=" * 80 + "\n")

    # =========================================================
    # STEP (1): Load packets & bind expected actions
    # =========================================================
    packets = load_test_packets(testset_file)
    rule_actions = load_rules_with_action(rules_file)

    for pkt in packets:
        rid = pkt['rule_index']
        pkt['expected_action'] = rule_actions.get(rid)

    log_file.write(f"Loaded {len(packets)} packets\n")
    log_file.write(f"Loaded {len(rule_actions)} rules with actions\n")

    # =========================================================
    # STEP (2): Final IP table match
    # =========================================================
    final_ip_table = load_final_ip_table(final_ip_table_file)
    ip_fail = 0

    for pkt in packets:
        gids = match_packet_to_final_ip_table(pkt, final_ip_table)
        if gids is None:
            pkt['fail_stage'] = FailStage.IP
            pkt['fail_reason'] = "No IP/Protocol match in final IP table"
            ip_fail += 1
            add_debug(pkt, FailStage.IP, {
                'src_ip': pkt['src_ip'],
                'dst_ip': pkt['dst_ip'],
                'protocol': pkt['protocol'],
            })
        else:
            pkt['matched_gids'] = gids

    log_file.write(f"Loaded {len(final_ip_table)} final IP rules\n")
    log_file.write("\nSTEP (2) summary:\n")
    log_file.write(f"Packets failed at IP stage: {ip_fail}\n")

    # ========================= 原有失败打印：完全保留 =========================
    if ip_fail > 0:
        log_file.write("\nSTEP (2) Failed packets details:\n")
        for pkt in packets:
            if pkt['fail_stage'] == FailStage.IP:
                log_file.write(
                    f"  Pkt#{pkt['packet_index']} "
                    f"SRC={pkt['src_ip']} DST={pkt['dst_ip']} PROTO={pkt['protocol']} "
                    f"G-ID1=None (no match)\n"
                )

    # =========================================================
    # STEP (3) + (3.5): SRC TCAM + SRC SRAM
    # =========================================================
    src_tcam_table = load_src_tcam_table(src_tcam_file)
    src_sram_table = load_src_sram_table(src_sram_file)

    src_fail = 0
    for pkt in packets:
        if pkt['fail_stage'] is not None:
            continue

        if src_tcam_lookup(pkt, src_tcam_table):
            continue

        if not src_sram_lookup(pkt, src_sram_table):
            src_fail += 1

    log_file.write("\nSTEP (3+3.5) summary:\n")
    log_file.write(f"Packets failed at SRC stage: {src_fail}\n")

    # ========================= 原有失败打印：完全保留 =========================
    if src_fail > 0:
        log_file.write("\nSTEP (3+3.5) Failed packets details:\n")
        for pkt in packets:
            if pkt['fail_stage'] in (FailStage.SRC_TCAM, FailStage.SRC_SRAM):
                quotient = pkt['src_port'] // 32
                remainder = pkt['src_port'] % 32
                log_file.write(
                    f"  Pkt#{pkt['packet_index']} "
                    f"SRC={pkt['src_ip']}:{pkt['src_port']} "
                    f"G-ID1={pkt.get('matched_gids', [])} "
                    f"G-ID2=None "
                    f"Stage={pkt['fail_stage']} "
                    f"Reason={pkt.get('fail_reason')}\n"
                )
                log_file.write(
                    f"    SRAM_Quotient={quotient} SRAM_BitIndex={remainder}\n"
                )

    # =========================================================
    # STEP (4): DST TCAM + DST SRAM
    # =========================================================
    dst_tcam_table = load_dst_tcam_table(dst_tcam_file)
    dst_sram_table = load_dst_sram_table(dst_sram_file)

    dst_fail = 0
    for pkt in packets:
        if pkt['fail_stage'] is not None:
            continue

        if dst_tcam_lookup(pkt, dst_tcam_table):
            continue

        if not dst_sram_lookup(pkt, dst_sram_table):
            dst_fail += 1

    log_file.write("\nSTEP (4) summary:\n")
    log_file.write(f"Packets failed at DST stage: {dst_fail}\n")

    # =========================================================
    # STEP (5): Action resolution & verification
    # =========================================================
    # 注意：现在不再需要 action_table，因为 action 直接从 DST 表中获取
    # action_table = build_action_table_from_rules(rules_file)  # 不再需要

    action_fail = 0
    action_mismatch = 0

    for pkt in packets:
        if pkt['fail_stage'] is not None and pkt['fail_stage'] != FailStage.ACTION:
            continue

        # action 应该已经在 DST lookup 阶段设置
        # 这里只需要验证 action 是否存在
        if 'resolved_action' not in pkt:
            pkt['fail_stage'] = FailStage.ACTION
            pkt['fail_reason'] = "Action not resolved from DST lookup"
            action_fail += 1
            continue

        # 验证 action 是否匹配期望值
        if pkt.get('expected_action') != pkt.get('resolved_action'):
            pkt['fail_stage'] = FailStage.ACTION
            pkt['fail_reason'] = f"Resolved action mismatch: expected {pkt.get('expected_action')}, got {pkt.get('resolved_action')}"
            action_mismatch += 1

    log_file.write("\nSTEP (5) summary:\n")
    log_file.write(f"Packets failed at ACTION stage: {action_fail}\n")
    log_file.write(f"Packets with action mismatch: {action_mismatch}\n")

    # =========================================================
    # Complete failed packet dump (FULL TRACE)
    # =========================================================
    log_file.write("\n" + "=" * 80 + "\n")
    log_file.write("Complete Failed Packets Summary (FULL PIPELINE TRACE)\n")
    log_file.write("=" * 80 + "\n")

    for pkt in packets:
        if pkt['fail_stage'] is None:
            continue

        log_file.write(f"\nPkt#{pkt['packet_index']} FAILED at {pkt['fail_stage']}\n")
        log_file.write(
            f"  SRC={pkt['src_ip']}:{pkt['src_port']} "
            f"DST={pkt['dst_ip']}:{pkt['dst_port']} "
            f"PROTO={pkt['protocol']}\n"
        )
        log_file.write(f"  G-ID1: {pkt.get('matched_gids')}\n")
        log_file.write(f"  G-ID2: {pkt.get('src_group_id')}\n")
        log_file.write(f"  Expected: {pkt.get('expected_action')}\n")
        log_file.write(f"  Resolved: {pkt.get('resolved_action')}\n")
        log_file.write(f"  Reason: {pkt.get('fail_reason')}\n")

        for trace in pkt.get('debug_trace', []):
            log_file.write(f"    [{trace['stage']}]: {trace['info']}\n")

    # =========================================================
    # FINAL SUMMARY  ⭐（这是你新加的需求）
    # =========================================================
    total_packets = len(packets)
    success_packets = sum(1 for pkt in packets if pkt.get('fail_stage') is None)
    recognition_rate = (success_packets / total_packets * 100.0) if total_packets else 0.0

    log_file.write("\nFINAL SUMMARY:\n")
    log_file.write(f"Total packets processed : {total_packets}\n")
    log_file.write(f"Successfully recognized : {success_packets}\n")
    log_file.write(f"Recognition rate        : {recognition_rate:.2f}%\n")

    log_file.close()
    print(f"Log written to {log_file_path}")
    return 0






if __name__ == "__main__":
    sys.exit(main())
