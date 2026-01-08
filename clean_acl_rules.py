#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

INPUT_FILE  = "./src/ACL_rules/acl4/acl4_50k_16_0.5.rules"
OUTPUT_FILE = "./src/ACL_rules/acl4/acl4_50k_16_0.5_c.rules"

def clean_rules(input_path, output_path):
    """
    若前五元组 + proto 完全相同，则统一使用第一次出现的 action
    且保持原始格式，仅替换最后一个字段
    """

    first_action = {}   # key (all tokens except last) -> action
    output_lines = []

    with open(input_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            raw = line.rstrip("\n")
            if not raw:
                output_lines.append(raw)
                continue

            # 保留原始 token 结构（tab / space 都能处理）
            tokens = raw.split()

            if len(tokens) < 2:
                print(f"[Warning] Line {line_no} too short: {raw}")
                output_lines.append(raw)
                continue

            key = tuple(tokens[:-1])   # 除 action 外的所有字段
            action = tokens[-1]

            if key not in first_action:
                first_action[key] = action
                final_action = action
            else:
                final_action = first_action[key]

            # 只替换最后一个 token
            new_tokens = list(tokens)
            new_tokens[-1] = final_action

            # 用 tab 还原（与原 rules 文件一致）
            output_lines.append("\t".join(new_tokens))

    with open(output_path, "w", encoding="utf-8") as f:
        for line in output_lines:
            f.write(line + "\n")

    print(f"[OK] Cleaned file written to: {output_path}")
    print(f"[INFO] Unique rule keys: {len(first_action)}")


if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"[Error] File not found: {INPUT_FILE}")
    else:
        clean_rules(INPUT_FILE, OUTPUT_FILE)
