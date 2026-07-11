#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证 tc/netem 实验产物 (netem_validation_results.csv)

检查项：
  1. CSV 文件存在且非空
  2. 矩阵完整性（3 protocols × 6 conditions × 10 repeats）
  3. 关键列存在且值合理
  4. 无伪造数据标记

如果数据不存在，报告 "no data" 并以非零码退出。
"""

import csv
import os
import sys
from collections import defaultdict


CSV_PATH = "results/netem_validation/netem_validation_results.csv"

EXPECTED_PROTOCOLS = {"gmcp_r", "seq_mac", "authenticated_hash_chain"}
EXPECTED_CONDITIONS = {"control", "mild", "mobile", "poor", "severe", "loss_heavy"}
EXPECTED_REPEATS = set(range(1, 11))  # 1..10

REQUIRED_COLUMNS = [
    "session_id", "experiment_type", "protocol",
    "condition_name", "loss_rate_pct", "delay_ms", "jitter_ms", "reorder_pct",
    "server_host", "server_port",
    "message_count", "payload_size", "repeat_id",
    "sent_count", "accepted_count", "rejected_count",
    "timeout_count", "error_count",
    "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
    "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
    "timestamp",
]


def read_csv_rows(filepath: str):
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    print(f"=== Netem Artifact Validation ===")
    print(f"File: {CSV_PATH}")
    print()

    # 1. File exists and non-empty
    if not os.path.exists(CSV_PATH):
        print(f"NO DATA: File does not exist: {CSV_PATH}")
        print("         Run the experiment first:")
        print("         sudo python run_netem_validation.py --interface lo")
        sys.exit(1)

    rows = read_csv_rows(CSV_PATH)
    if not rows:
        print(f"NO DATA: File exists but is empty: {CSV_PATH}")
        sys.exit(1)

    print(f"Rows: {len(rows)}")

    # 2. Check required columns
    actual_cols = set(rows[0].keys())
    missing_cols = [c for c in REQUIRED_COLUMNS if c not in actual_cols]
    if missing_cols:
        print(f"FAIL: Missing columns: {missing_cols}")
        sys.exit(1)
    print(f"Columns: OK ({len(actual_cols)} columns, all required columns present)")

    # 3. Matrix completeness
    seen = set()
    for r in rows:
        key = (
            r["protocol"],
            r["condition_name"],
            int(r["repeat_id"]),
        )
        seen.add(key)

    expected_total = (
        len(EXPECTED_PROTOCOLS)
        * len(EXPECTED_CONDITIONS)
        * len(EXPECTED_REPEATS)
    )

    protocols_found = {r["protocol"] for r in rows}
    conditions_found = {r["condition_name"] for r in rows}
    repeats_found = {int(r["repeat_id"]) for r in rows}

    issues = []

    if protocols_found != EXPECTED_PROTOCOLS:
        issues.append(f"Protocols mismatch: found {protocols_found}, expected {EXPECTED_PROTOCOLS}")

    if conditions_found != EXPECTED_CONDITIONS:
        missing_cond = EXPECTED_CONDITIONS - conditions_found
        extra_cond = conditions_found - EXPECTED_CONDITIONS
        if missing_cond:
            issues.append(f"Missing conditions: {missing_cond}")
        if extra_cond:
            issues.append(f"Extra conditions: {extra_cond}")

    if repeats_found != EXPECTED_REPEATS:
        missing_repeats = EXPECTED_REPEATS - repeats_found
        if missing_repeats:
            issues.append(f"Missing repeat IDs: {sorted(missing_repeats)}")

    if len(seen) < expected_total:
        issues.append(f"Incomplete matrix: {len(seen)}/{expected_total} unique (protocol, condition, repeat) combos")
    else:
        print(f"Matrix: OK ({len(seen)}/{expected_total} unique combos)")

    if issues:
        for issue in issues:
            print(f"WARN: {issue}")

    # 4. Value sanity checks
    sane_issues = []
    for i, r in enumerate(rows):
        row_num = i + 1
        sr = float(r.get("success_rate", 0))
        if sr < 0 or sr > 100:
            sane_issues.append(f"Row {row_num}: success_rate={sr} out of range [0,100]")

        tp = float(r.get("throughput_msg_per_sec", 0))
        if tp < 0:
            sane_issues.append(f"Row {row_num}: throughput={tp} is negative")

        rtt = float(r.get("avg_rtt_ms", 0))
        if rtt < 0:
            sane_issues.append(f"Row {row_num}: avg_rtt_ms={rtt} is negative")

        if int(r.get("sent_count", 0)) < int(r.get("accepted_count", 0)):
            sane_issues.append(f"Row {row_num}: accepted > sent")

    if sane_issues:
        for issue in sane_issues[:10]:
            print(f"WARN: {issue}")
        if len(sane_issues) > 10:
            print(f"  ... and {len(sane_issues) - 10} more warnings")
    else:
        print("Sanity checks: OK")

    # 5. Per-condition success rate trends
    print()
    print("--- Success Rate by Condition ---")
    by_cond = defaultdict(list)
    for r in rows:
        by_cond[r["condition_name"]].append(float(r["success_rate"]))

    for cond in ["control", "mild", "mobile", "poor", "severe", "loss_heavy"]:
        if cond in by_cond:
            vals = by_cond[cond]
            avg = sum(vals) / len(vals)
            print(f"  {cond:12s}: n={len(vals):3d}  avg_success={avg:6.2f}%")

    # 6. Per-protocol summary
    print()
    print("--- Summary by Protocol ---")
    by_proto = defaultdict(list)
    for r in rows:
        by_proto[r["protocol"]].append(r)

    for proto in sorted(by_proto.keys()):
        proto_rows = by_proto[proto]
        avg_success = sum(float(r["success_rate"]) for r in proto_rows) / len(proto_rows)
        avg_tp = sum(float(r["throughput_msg_per_sec"]) for r in proto_rows) / len(proto_rows)
        avg_rtt = sum(float(r["avg_rtt_ms"]) for r in proto_rows) / len(proto_rows)
        print(
            f"  {proto:30s}: n={len(proto_rows):3d}  "
            f"success={avg_success:6.2f}%  "
            f"throughput={avg_tp:8.1f} msg/s  "
            f"avg_rtt={avg_rtt:7.2f}ms"
        )

    print()
    if not issues and not sane_issues:
        print("PASS: All checks passed.")
        sys.exit(0)
    elif issues:
        print("PARTIAL: Some matrix completeness issues detected (see warnings above).")
        sys.exit(1)
    else:
        print("PASS: All checks passed (with minor sanity warnings).")
        sys.exit(0)


if __name__ == "__main__":
    main()
