#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证 tc/netem 实验产物 (netem_validation_results.csv)

严格检查项：
  1. CSV 文件存在且非空
  2. 矩阵完整性（3 protocols × 6 conditions × 10 repeats = 180 行）
  3. 关键列存在且值合理
  4. execution_valid=True（非 control 行）
  5. server_git_dirty=false, client_git_dirty=false
  6. server_git_commit, client_git_commit 长度=40
  7. tc 参数匹配（actual_delay/loss 在 requested * 0.8 以上）
  8. control 条件确认无 netem 残留
  9. 不强制 100% success_rate（真实网络现象）

任何 issue / sane_issue / exec_issue / tc_issue 均以非零码退出。
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
    "execution_valid", "interface", "requested_netem_config", "actual_qdisc_config",
    "actual_delay_ms", "actual_loss_pct", "actual_jitter_ms",
    "execution_mode", "impairment_direction", "tc_endpoint",
    "server_git_commit", "server_git_dirty",
    "client_git_commit", "client_git_dirty",
    "client_hostname", "client_cpu_model",
    "client_python_version", "client_os_info",
    "command_line",
    "state_match",
    "timestamp",
]

# Condition name → (requested_delay_ms, requested_loss_pct)
CONDITION_PARAMS = {
    "control":   (0, 0, 0, 0),
    "mild":      (30, 1, 10, 0),
    "mobile":    (60, 2, 30, 5),
    "poor":      (100, 5, 50, 5),
    "severe":    (200, 10, 80, 10),
    "loss_heavy": (50, 20, 20, 5),
}


def read_csv_rows(filepath: str):
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    print(f"=== Netem Artifact Validation (strict) ===")
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

    # 3. Matrix completeness (must be exactly 180 rows)
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

    if len(rows) != expected_total:
        issues.append(f"Row count mismatch: {len(rows)} != expected {expected_total}")

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
            print(f"TC FAIL: {issue}")
        if len(sane_issues) > 10:
            print(f"  ... and {len(sane_issues) - 10} more warnings")
    else:
        print("Sanity checks: OK")

    # 5. Strict execution_valid checks (non-control conditions)
    exec_issues = []
    for i, r in enumerate(rows):
        row_num = i + 1
        cond = r.get("condition_name", "")
        exec_v = r.get("execution_valid", "")
        git_c = r.get("server_git_commit", "")
        git_dirty = r.get("server_git_dirty", "")
        client_gc = r.get("client_git_commit", "")
        client_dirty = r.get("client_git_dirty", "")
        state_m = r.get("state_match", "")

        # server_git_commit must be non-empty
        if not git_c:
            exec_issues.append(f"Row {row_num}: server_git_commit is empty")

        # server_git_commit length must be 40
        if git_c and len(git_c) != 40:
            exec_issues.append(f"Row {row_num}: server_git_commit length={len(git_c)} (expected 40)")

        # server_git_dirty must be false (if column exists)
        if "server_git_dirty" in r and str(git_dirty).lower() != "false":
            exec_issues.append(f"Row {row_num}: server_git_dirty={git_dirty} (expected false)")

        # client_git_commit must be non-empty
        if not client_gc:
            exec_issues.append(f"Row {row_num}: client_git_commit is empty")

        # client_git_commit length must be 40
        if client_gc and len(client_gc) != 40:
            exec_issues.append(f"Row {row_num}: client_git_commit length={len(client_gc)} (expected 40)")

        # client_git_dirty must be false
        if "client_git_dirty" in r and str(client_dirty).lower() != "false":
            exec_issues.append(f"Row {row_num}: client_git_dirty={client_dirty} (expected false)")

        # state_match should exist
        if state_m == "":
            exec_issues.append(f"Row {row_num}: state_match is empty")

        # All conditions must have execution_valid=True
        if str(exec_v).lower() != "true":
            exec_issues.append(f"Row {row_num}: condition={cond} but execution_valid={exec_v}")

        # Control conditions must not have netem in actual_qdisc_config
        if cond == "control":
            actual_qdisc = r.get("actual_qdisc_config", "")
            if "netem" in actual_qdisc:
                exec_issues.append(f"Row {row_num}: control condition has netem in actual_qdisc_config")

    # 6. tc parameter matching (actual vs requested)
    tc_issues = []
    for i, r in enumerate(rows):
        row_num = i + 1
        cond = r.get("condition_name", "")

        if cond == "control":
            continue  # control has no tc parameters

        if cond not in CONDITION_PARAMS:
            tc_issues.append(f"Row {row_num}: unknown condition '{cond}'")
            continue

        req_delay, req_loss, req_jitter, req_reorder = CONDITION_PARAMS[cond]

        try:
            actual_delay = float(r.get("actual_delay_ms", 0))
            actual_loss = float(r.get("actual_loss_pct", 0))
            actual_jitter = float(r.get("actual_jitter_ms", 0))
            actual_reorder = float(r.get("actual_reorder_pct", 0))
        except (ValueError, TypeError):
            tc_issues.append(f"Row {row_num}: cannot parse actual tc parameters")
            continue

        tol = 0.25
        if req_delay > 0 and abs(actual_delay - req_delay) > req_delay * tol:
            tc_issues.append(f"Row {row_num}: actual_delay={actual_delay:.1f}ms vs requested={req_delay}ms")
        if req_loss > 0 and abs(actual_loss - req_loss) > req_loss * tol:
            tc_issues.append(f"Row {row_num}: actual_loss={actual_loss:.1f}% vs requested={req_loss}%")
        if req_jitter > 0 and abs(actual_jitter - req_jitter) > req_jitter * tol:
            tc_issues.append(f"Row {row_num}: actual_jitter={actual_jitter:.1f}ms vs requested={req_jitter}ms")
        if req_reorder > 0 and abs(actual_reorder - req_reorder) > req_reorder * tol:
            tc_issues.append(f"Row {row_num}: actual_reorder={actual_reorder:.1f}% vs requested={req_reorder}%")

    if tc_issues:
        for issue in tc_issues[:10]:
            print(f"TC FAIL: {issue}")
        if len(tc_issues) > 10:
            print(f"  ... and {len(tc_issues) - 10} more warnings")
    else:
        print("tc parameter checks: OK")

    # 7. Per-condition success rate trends
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

    # 8. Per-protocol summary
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

    # 9. Final verdict — strict: any issue type → FAIL
    print()
    all_critical = issues + sane_issues + exec_issues + tc_issues

    if all_critical:
        for issue in all_critical:
            print(f"FAIL: {issue}")
        print(f"\nFAIL: {len(all_critical)} critical issue(s) found. Exiting with error.")
        sys.exit(1)
    else:
        print("PASS: All checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
