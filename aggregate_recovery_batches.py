#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
聚合器：恢复实验batch CSV合并
=============================

读取多个batch CSV（每个batch是一个repeat），验证完整性后合并为最终结果。

验证项：
  V01  Batch文件数量 == 重复次数
  V02  Repeat IDs可从文件名解析
  V03  Repeat ID集合完整
  V04  每个batch行数 == 矩阵组合数
  V05  每行repeat_id匹配batch ID
  V06  每行run_valid == True
  V07  每行total_accepted == message_count
  V08  每行unrecovered_count == 0
  V09  每行client_git_commit长度 == 40
  V10  每行client_git_dirty == false
  V11  每行server_git_dirty == false
  V12  协议特定状态匹配（memory_match / hash_match）
  V13  总行数 == 重复次数 × 矩阵组合数
  V14  每个配置出现恰好N次
  V15  全局唯一client_git_commit
  V16  所有session_ids唯一
  V17  schema_version == 2
  V18  disconnect_point在结果中记录
  V19  disconnect_type在结果中记录
  V20  reconnect_success字段存在

使用方法：
    python3 aggregate_recovery_batches.py \
        --batch-dir /path/to/batches \
        --output /path/to/recovery_results.csv
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

EXPECTED_PROTOCOLS = {"gmcp_r", "seq_mac", "authenticated_hash_chain"}
EXPECTED_DISCONNECT_POINTS = {50, 250, 450}
EXPECTED_DISCONNECT_TYPES = {"client_close", "server_close"}
DEFAULT_REPEAT_COUNT = 10
ROWS_PER_BATCH = len(EXPECTED_PROTOCOLS) * len(EXPECTED_DISCONNECT_POINTS) * len(EXPECTED_DISCONNECT_TYPES)


def load_batch(path: Path) -> list:
    """Load a batch CSV and return rows."""
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def validate_batch(rows: list, repeat_id: int, batch_path: Path) -> list:
    """Validate a single batch. Returns list of error messages (empty = OK)."""
    errors = []

    # V04: Per-batch row count
    if len(rows) != ROWS_PER_BATCH:
        errors.append(f"{batch_path.name}: expected {ROWS_PER_BATCH} rows, got {len(rows)}")

    for i, r in enumerate(rows, 1):
        ctx = f"{batch_path.name} row {i}"

        # V05: repeat_id must match batch ID
        rid = int(r.get("repeat_id", -1))
        if rid != repeat_id:
            errors.append(f"{ctx}: repeat_id={rid}, expected {repeat_id}")

        # V06: run_valid must be True
        if r.get("run_valid") not in ("True", "true", True):
            errors.append(f"{ctx}: run_valid={r.get('run_valid')}")

        # V07: total_accepted == message_count
        if int(r.get("total_accepted", -1)) != int(r.get("message_count", -2)):
            errors.append(f"{ctx}: total_accepted != message_count")

        # V08: unrecovered_count == 0
        unrecovered = int(r.get("unrecovered_count", -1))
        if unrecovered != 0:
            errors.append(f"{ctx}: unrecovered_count={unrecovered}")

        # V09: client_git_commit 40 chars
        commit = r.get("client_git_commit", "")
        if len(commit) != 40:
            errors.append(f"{ctx}: client_git_commit length {len(commit)} != 40")

        # V10: client_git_dirty = false
        if r.get("client_git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: client_git_dirty={r.get('client_git_dirty')}")

        # V11: server_git_dirty = false
        if r.get("server_git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: server_git_dirty={r.get('server_git_dirty')}")

        # V12: protocol-specific state match
        proto = r.get("protocol", "")
        if proto == "gmcp_r" and r.get("memory_match") not in ("True", "true", True):
            errors.append(f"{ctx}: gmcp_r memory_match={r.get('memory_match')}")
        if proto == "authenticated_hash_chain" and r.get("hash_match") not in ("True", "true", True):
            errors.append(f"{ctx}: AHC hash_match={r.get('hash_match')}")

        # V17: schema_version must be '2'
        sv = r.get("schema_version", "")
        if sv != "2":
            errors.append(f"{ctx}: schema_version={sv!r}, expected '2'")

        # V18: disconnect_point must exist
        dp = r.get("disconnect_point", "")
        if not dp:
            errors.append(f"{ctx}: disconnect_point missing")

        # V19: disconnect_type must exist
        dt = r.get("disconnect_type", "")
        if not dt:
            errors.append(f"{ctx}: disconnect_type missing")

        # V20: reconnect_success must exist
        rs = r.get("reconnect_success", "")
        if rs == "":
            errors.append(f"{ctx}: reconnect_success missing")

    return errors


def validate_all(
    batch_dir: Path,
    repeat_count: int = DEFAULT_REPEAT_COUNT,
) -> Tuple[List[str], list]:
    """Run all validations. Returns (errors, all_rows)."""
    errors: List[str] = []

    # V01: Find batch files
    batch_files = sorted(batch_dir.glob("recovery_batch_r*.csv"))
    batch_files = [f for f in batch_files if not f.name.endswith(".failed.csv")]

    if len(batch_files) != repeat_count:
        msg = f"V01 FAIL: expected {repeat_count} batch files, found {len(batch_files)}"
        for f in batch_files:
            msg += f"\n  {f.name}"
        return [msg], []

    # V02: Parse repeat IDs from filenames
    repeat_ids = set()
    for f in batch_files:
        try:
            rid = int(f.stem.split("_r")[1])
            repeat_ids.add(rid)
        except (IndexError, ValueError):
            return [f"V02 FAIL: cannot parse repeat_id from {f.name}"], []

    # V03: repeat_id set complete
    expected_ids = set(range(1, repeat_count + 1))
    if repeat_ids != expected_ids:
        missing = expected_ids - repeat_ids
        extra = repeat_ids - expected_ids
        return [f"V03 FAIL: repeat_id mismatch. missing={missing}, extra={extra}"], []

    # V04-V20: Load and validate all batches
    all_rows: list = []
    batch_errors: List[str] = []

    for f in batch_files:
        rid = int(f.stem.split("_r")[1])
        rows = load_batch(f)
        errs = validate_batch(rows, rid, f)
        if errs:
            batch_errors.extend(errs)
        all_rows.extend(rows)

    if batch_errors:
        errors.extend(batch_errors)

    # V13: Total rows
    expected_total = ROWS_PER_BATCH * repeat_count
    if len(all_rows) != expected_total:
        errors.append(f"V13 FAIL: expected {expected_total} total rows, got {len(all_rows)}")

    # V14: Each config appears exactly repeat_count times
    configs = Counter(
        (r["protocol"], int(r["disconnect_point"]), r["disconnect_type"])
        for r in all_rows
    )
    for key in sorted(configs):
        if configs[key] != repeat_count:
            errors.append(f"V14 FAIL: {key} has {configs[key]} rows, expected {repeat_count}")

    # V15: Unique client_git_commit
    commits = set(r.get("client_git_commit", "") for r in all_rows)
    if len(commits) != 1:
        errors.append(f"V15 FAIL: {len(commits)} different client commits")

    # V16: All session_ids unique
    session_ids = [r.get("session_id", "") for r in all_rows]
    if len(session_ids) != len(set(session_ids)):
        dups = len(session_ids) - len(set(session_ids))
        errors.append(f"V16 FAIL: {dups} duplicate session_ids")

    return errors, all_rows


def main():
    parser = argparse.ArgumentParser(description="Aggregate recovery formal batches")
    parser.add_argument("--batch-dir", required=True, help="Directory containing batch CSVs")
    parser.add_argument("--output", required=True, help="Output path for recovery_results.csv")
    parser.add_argument("--repeat-count", type=int, default=DEFAULT_REPEAT_COUNT,
        help="Expected number of repeats (default: 10)")
    args = parser.parse_args()

    batch_dir = Path(args.batch_dir)
    output_path = Path(args.output)
    tmp_path = Path(str(output_path) + ".tmp")

    if output_path.exists():
        print(f"[AGGREGATE] FAIL: output already exists: {output_path}")
        print("  Formal aggregate results are immutable; choose a clean output path.")
        sys.exit(1)
    if tmp_path.exists():
        print(f"[AGGREGATE] FAIL: tmp output already exists: {tmp_path}")
        sys.exit(1)

    errors, all_rows = validate_all(batch_dir, args.repeat_count)

    if errors:
        print(f"[AGGREGATE] FAIL: {len(errors)} validation errors:")
        for e in errors[:30]:
            for line in str(e).split("\n"):
                print(f"  {line}")
        if len(errors) > 30:
            print(f"  ... and {len(errors) - 30} more")
        sys.exit(1)

    # Atomic publish
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(all_rows[0].keys())

    with tmp_path.open("x", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
        f.flush()
        os.fsync(f.fileno())

    os.link(tmp_path, output_path)
    tmp_path.unlink()

    sha = hashlib.sha256(open(str(output_path), "rb").read()).hexdigest()
    proto_counts = Counter(r["protocol"] for r in all_rows)
    commits = set(r.get("client_git_commit", "") for r in all_rows)
    print(f"[AGGREGATE] OK: {len(all_rows)} rows published")
    print(f"[AGGREGATE] Output: {output_path}")
    print(f"[AGGREGATE] SHA-256: {sha}")
    print(f"[AGGREGATE] Protocols: {dict(proto_counts)}")
    print(f"[AGGREGATE] Commit: {list(commits)[0]}")


if __name__ == "__main__":
    main()
