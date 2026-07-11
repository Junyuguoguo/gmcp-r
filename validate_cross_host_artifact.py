#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证跨主机实验产物 (cross_host_results.csv)

强制检查项：
  1. CSV 文件存在且非空
  2. 矩阵完整性（5 protocols × 2 msg_counts × 2 payloads × 20 repeats = 400 行）
  3. 无重复组合
  4. run_valid = True（所有行）
  5. git_dirty = false（所有行）
  6. git_commit 长度 = 40
  7. state_match = True（所有行）— 独立比较
  8. accepted == message_count（所有行）
  9. rejected == 0, timeout == 0, error == 0（所有行）
 10. server_git_commit 非空（所有行）

如果数据不存在，报告 "no data" 并以非零码退出。
"""

import csv
import os
import sys
from collections import defaultdict


CSV_PATH = "results/cross_host/cross_host_results.csv"

EXPECTED_PROTOCOLS = {"gmcp_r", "seq_mac", "hash_chain", "authenticated_hash_chain", "ticket_only"}
EXPECTED_MSG_COUNTS = {500, 1000}
EXPECTED_PAYLOAD_SIZES = {128, 512}
EXPECTED_REPEATS = set(range(1, 21))  # 1..20
EXPECTED_TOTAL = 5 * 2 * 2 * 20  # 400

REQUIRED_COLUMNS = [
    "session_id", "experiment_type", "protocol",
    "client_host_id", "server_host_id", "network_path_type",
    "server_host", "server_port", "tcp_connect_latency_ms",
    "message_count", "payload_size", "repeat_id",
    "sent_count", "accepted_count", "rejected_count",
    "timeout_count", "error_count",
    "unrecovered",
    "client_final_seq", "server_final_seq", "sequence_match",
    "client_final_mem", "server_final_mem", "memory_match",
    "client_final_hash", "server_final_hash", "hash_match",
    "state_match", "run_valid",
    "success_rate", "throughput_msg_per_sec", "elapsed_seconds",
    "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
    "timestamp",
    "git_commit", "git_branch", "git_dirty",
    "server_git_commit", "server_python_version", "server_os_info", "server_hostname",
]


def read_csv_rows(filepath: str):
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    errors = []

    print(f"=== Cross-Host Artifact Validation (Enhanced) ===")
    print(f"File: {CSV_PATH}")
    print()

    # 1. File exists and non-empty
    if not os.path.exists(CSV_PATH):
        print(f"NO DATA: File does not exist: {CSV_PATH}")
        print("         Run the experiment first:")
        print("         python run_cross_host_validation.py --host <server-ip> --port 9001 --no-spawn-server")
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
        errors.append(f"Missing columns: {missing_cols}")
    else:
        print(f"Columns: OK ({len(actual_cols)} columns, all required columns present)")

    # 3. Matrix completeness (400 rows)
    if len(rows) != EXPECTED_TOTAL:
        errors.append(f"Row count: expected {EXPECTED_TOTAL}, got {len(rows)}")
    else:
        print(f"Row count: OK ({len(rows)}/{EXPECTED_TOTAL})")

    # 4. No duplicate combos
    seen = set()
    for i, r in enumerate(rows):
        key = (
            r["protocol"],
            int(r["message_count"]),
            int(r["payload_size"]),
            int(r["repeat_id"]),
        )
        if key in seen:
            errors.append(f"Duplicate combo at row {i+1}: {key}")
        seen.add(key)

    # 5. Matrix completeness check
    protocols_found = {r["protocol"] for r in rows}
    msg_counts_found = {int(r["message_count"]) for r in rows}
    payloads_found = {int(r["payload_size"]) for r in rows}
    repeats_found = {int(r["repeat_id"]) for r in rows}

    if protocols_found != EXPECTED_PROTOCOLS:
        errors.append(f"Protocols mismatch: found {protocols_found}, expected {EXPECTED_PROTOCOLS}")
    if msg_counts_found != EXPECTED_MSG_COUNTS:
        errors.append(f"Message counts mismatch: found {msg_counts_found}, expected {EXPECTED_MSG_COUNTS}")
    if payloads_found != EXPECTED_PAYLOAD_SIZES:
        errors.append(f"Payload sizes mismatch: found {payloads_found}, expected {EXPECTED_PAYLOAD_SIZES}")
    if repeats_found != EXPECTED_REPEATS:
        missing_repeats = EXPECTED_REPEATS - repeats_found
        if missing_repeats:
            errors.append(f"Missing repeat IDs: {sorted(missing_repeats)}")

    if len(seen) == EXPECTED_TOTAL and not errors:
        print(f"Matrix: OK ({len(seen)}/{EXPECTED_TOTAL} unique combos, no duplicates)")

    # 6. Per-row strict checks
    for i, r in enumerate(rows):
        row_num = i + 1

        # run_valid must be True
        rv = r.get("run_valid", "")
        if str(rv).lower() != "true":
            errors.append(f"Row {row_num}: run_valid={rv} (must be True)")

        # git_dirty must be false
        gd = r.get("git_dirty", "")
        if str(gd).lower() != "false":
            errors.append(f"Row {row_num}: git_dirty={gd} (must be false)")

        # git_commit must be length 40 (SHA-1)
        gc = r.get("git_commit", "")
        if len(gc) != 40:
            errors.append(f"Row {row_num}: git_commit length={len(gc)} (must be 40)")

        # state_match must be True (independent comparison)
        sm = r.get("state_match", "")
        if str(sm).lower() != "true":
            errors.append(f"Row {row_num}: state_match={sm} (must be True, independent comparison)")

        # accepted == message_count
        acc = int(r.get("accepted_count", 0))
        mc = int(r.get("message_count", 0))
        if acc != mc:
            errors.append(f"Row {row_num}: accepted_count={acc} != message_count={mc}")

        # rejected == 0
        rej = int(r.get("rejected_count", 0))
        if rej != 0:
            errors.append(f"Row {row_num}: rejected_count={rej} (must be 0)")

        # timeout == 0
        toc = int(r.get("timeout_count", 0))
        if toc != 0:
            errors.append(f"Row {row_num}: timeout_count={toc} (must be 0)")

        # error == 0
        ec = int(r.get("error_count", 0))
        if ec != 0:
            errors.append(f"Row {row_num}: error_count={ec} (must be 0)")

        # sequence_match must be True (if present)
        seqm = r.get("sequence_match", "True")
        if str(seqm).lower() != "true":
            errors.append(f"Row {row_num}: sequence_match={seqm} (must be True)")

        # server_git_commit must be non-empty
        sgc = r.get("server_git_commit", "")
        if not sgc:
            errors.append(f"Row {row_num}: server_git_commit is empty (must be non-empty)")

    # Report results
    print()
    if errors:
        print(f"FAIL: {len(errors)} error(s) found:")
        for e in errors[:30]:
            print(f"  - {e}")
        if len(errors) > 30:
            print(f"  ... and {len(errors) - 30} more errors")
        print()
        print("FAIL: Validation failed.")
        sys.exit(1)
    else:
        # Summary stats
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
        print("PASS: All checks passed.")
        print(f"  - {len(rows)} rows, matrix complete ({EXPECTED_TOTAL})")
        print(f"  - All run_valid=True")
        print(f"  - All git_dirty=false, git_commit=40 chars")
        print(f"  - All state_match=True (independent comparison)")
        print(f"  - All accepted=message_count, rejected=0, timeout=0, error=0")
        print(f"  - All server_git_commit non-empty")
        print(f"  - No duplicate combinations")
        sys.exit(0)


if __name__ == "__main__":
    main()
