#!/usr/bin/env python3
"""
Strict aggregator for cross-host formal experiment batches.

Reads 20 successful batch CSVs (cross_host_batch_rNN.csv) and produces
the final cross_host_results.csv via atomic publish.

17 atomic validations:
  V01  Batch file count == 20
  V02  Repeat IDs parseable from filenames
  V03  Repeat ID set == {1..20}
  V04  Per-batch row count == 20
  V05  Per-row repeat_id matches batch ID
  V06  Per-row run_valid == True
  V07  Per-row accepted_count == message_count
  V08  Per-row unrecovered (rejected + timeout + error) == 0
  V09  Per-row git_commit length == 40
  V10  Per-row git_dirty == false
  V11  Per-row server_git_dirty == false
  V12  Per-row protocol-specific state match (memory_match / hash_match)
  V13  Total rows == 400
  V14  Configuration set matches EXPECTED_CONFIGS
  V15  Each configuration appears exactly 20 times
  V16  Exactly 1 unique git_commit across all rows
  V17  All session_ids unique (no duplicates)
  V18  Per-row state_match == True
  V19  Per-row sequence_match == True
  V20  Per-row sent_count == message_count
  V21  Per-row failure_reason empty
  V22  Per-row network_path_type != loopback
  V23  Per-row client_host_id != server_hostname
  V24  Per-row server provenance non-empty
  V25  Per-row server_git_commit length == 40
  V26  client commit == server commit across all rows
  V27  Consistent client/server identity across batches
  V28  Each configuration appears exactly 20 times

Usage:
    python3 aggregate_cross_host_batches.py \\
        --batch-dir /path/to/batches \\
        --output results/cross_host/cross_host_results.csv
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

EXPECTED_REPEAT_IDS = set(range(1, 21))
ROWS_PER_BATCH = 20
EXPECTED_PROTOCOLS = {"gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"}
EXPECTED_CONFIGS = {
    (p, m, s)
    for p in EXPECTED_PROTOCOLS
    for m in (500, 1000)
    for s in (128, 512)
}


def load_batch(path: Path) -> list[dict]:
    """Load a batch CSV and return rows."""
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def validate_batch(rows: list[dict], repeat_id: int, batch_path: Path) -> list[str]:
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

        # V07: accepted == message_count
        if int(r.get("accepted_count", -1)) != int(r.get("message_count", -2)):
            errors.append(f"{ctx}: accepted != message_count")

        # V08: rejected + timeout + error == 0
        rejected = int(r.get("rejected_count", -1))
        timeout = int(r.get("timeout_count", -1))
        error = int(r.get("error_count", -1))
        if rejected + timeout + error != 0:
            errors.append(f"{ctx}: unrecovered={rejected + timeout + error} (rejected={rejected}, timeout={timeout}, error={error})")

        # V09: git_commit 40 chars
        commit = r.get("git_commit", "")
        if len(commit) != 40:
            errors.append(f"{ctx}: git_commit length {len(commit)} != 40")

        # V10: git_dirty = false
        if r.get("git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: git_dirty={r.get('git_dirty')}")

        # V11: server_git_dirty = false
        if r.get("server_git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: server_git_dirty={r.get('server_git_dirty')}")

        # V12: protocol-specific state match
        proto = r.get("protocol", "")
        if proto == "gmcp_r" and r.get("memory_match") not in ("True", "true", True):
            errors.append(f"{ctx}: gmcp_r memory_match={r.get('memory_match')}")
        if proto in ("hash_chain", "authenticated_hash_chain") and r.get("hash_match") not in ("True", "true", True):
            errors.append(f"{ctx}: {proto} hash_match={r.get('hash_match')}")

        # V18: state_match == True
        if r.get("state_match") not in ("True", "true", True):
            errors.append(f"{ctx}: state_match={r.get('state_match')}")

        # V19: sequence_match == True
        if r.get("sequence_match") not in ("True", "true", True):
            errors.append(f"{ctx}: sequence_match={r.get('sequence_match')}")

        # V20: sent_count == message_count
        if int(r.get("sent_count", -1)) != int(r.get("message_count", -2)):
            errors.append(f"{ctx}: sent_count != message_count")

        # V21: failure_reason empty
        if r.get("failure_reason", "").strip():
            errors.append(f"{ctx}: failure_reason={r.get('failure_reason')}")

        # V22: network_path_type != loopback
        if r.get("network_path_type", "").lower() == "loopback":
            errors.append(f"{ctx}: network_path_type=loopback")

        # V23: client_host_id != server_hostname
        if r.get("client_host_id") == r.get("server_hostname"):
            errors.append(f"{ctx}: client and server on same host")

        # V24: server provenance non-empty
        for field in ("server_hostname", "server_python_version", "server_os_info", "server_cpu_model"):
            if not r.get(field, "").strip():
                errors.append(f"{ctx}: {field} empty")

        # V25: server_git_commit 40 chars
        serv_commit = r.get("server_git_commit", "")
        if len(serv_commit) != 40:
            errors.append(f"{ctx}: server_git_commit length {len(serv_commit)} != 40")

    return errors


def validate_all(
    batch_dir: Path,
) -> Tuple[List[str], List[dict], str]:
    """
    Run all 17 atomic validations. Returns (errors, all_rows, sha_on_success).

    On success errors is empty and all_rows contains the aggregated data.
    On failure errors contains descriptive messages.
    """
    errors: List[str] = []

    # V01: Find all batch files, count == 20
    batch_files = sorted(batch_dir.glob("cross_host_batch_r*.csv"))
    batch_files = [f for f in batch_files if not f.name.endswith(".failed.csv")]

    if len(batch_files) != 20:
        msg = f"V01 FAIL: expected 20 batch files, found {len(batch_files)}"
        for f in batch_files:
            msg += f"\n  {f.name}"
        return [msg], [], ""

    # V02: Parse repeat IDs from filenames
    repeat_ids = set()
    for f in batch_files:
        try:
            rid = int(f.stem.split("_r")[1])
            repeat_ids.add(rid)
        except (IndexError, ValueError):
            return [f"V02 FAIL: cannot parse repeat_id from {f.name}"], [], ""

    # V03: repeat_id set == {1..20}
    if repeat_ids != EXPECTED_REPEAT_IDS:
        missing = EXPECTED_REPEAT_IDS - repeat_ids
        extra = repeat_ids - EXPECTED_REPEAT_IDS
        return [f"V03 FAIL: repeat_id mismatch. missing={missing}, extra={extra}"], [], ""

    # V04-V12: Load and validate all batches
    all_rows: list[dict] = []
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

    # V13: Total rows == 400
    if len(all_rows) != 400:
        errors.append(f"V13 FAIL: expected 400 total rows, got {len(all_rows)}")

    # V14: Configuration set matches EXPECTED_CONFIGS
    exact = Counter(
        (r["protocol"], int(r["message_count"]), int(r["payload_size"]))
        for r in all_rows
    )
    if set(exact) != EXPECTED_CONFIGS:
        missing = EXPECTED_CONFIGS - set(exact)
        extra = set(exact) - EXPECTED_CONFIGS
        errors.append(f"V14 FAIL: configuration mismatch. missing={missing}, extra={extra}")

    # V15: Each configuration appears exactly 20 times
    for key in sorted(EXPECTED_CONFIGS):
        if exact[key] != 20:
            errors.append(f"V15 FAIL: {key} has {exact[key]} rows, expected 20")

    # V16: Exactly 1 unique git_commit
    commits = set(r.get("git_commit", "") for r in all_rows)
    if len(commits) != 1:
        errors.append(f"V16 FAIL: {len(commits)} different client commits")

    # V17: All session_ids unique
    session_ids = [r.get("session_id", "") for r in all_rows]
    if len(session_ids) != len(set(session_ids)):
        dups = len(session_ids) - len(set(session_ids))
        errors.append(f"V17 FAIL: {dups} duplicate session_ids")

    # V26: client commit == server commit
    client_commits = set(r.get("git_commit", "") for r in all_rows)
    server_commits = set(r.get("server_git_commit", "") for r in all_rows)
    if client_commits != server_commits:
        errors.append(f"V26 FAIL: client commits {client_commits} != server commits {server_commits}")

    # V27: 20 batches consistent client/server identity
    client_hosts = set(r.get("client_host_id", "") for r in all_rows)
    server_hosts = set(r.get("server_hostname", "") for r in all_rows)
    if len(client_hosts) != 1:
        errors.append(f"V27 FAIL: {len(client_hosts)} different client hosts")
    if len(server_hosts) != 1:
        errors.append(f"V27 FAIL: {len(server_hosts)} different server hosts")

    # V28: All configurations exactly 20 times
    exact = Counter(
        (r["protocol"], int(r["message_count"]), int(r["payload_size"]))
        for r in all_rows
    )
    for key in sorted(EXPECTED_CONFIGS):
        if exact[key] != 20:
            errors.append(f"V28 FAIL: {key} has {exact[key]} rows, expected 20")

    return errors, all_rows, ""


def main():
    parser = argparse.ArgumentParser(description="Aggregate cross-host formal batches")
    parser.add_argument("--batch-dir", required=True, help="Directory containing batch CSVs")
    parser.add_argument("--output", required=True, help="Output path for cross_host_results.csv")
    args = parser.parse_args()

    batch_dir = Path(args.batch_dir)
    output_path = Path(args.output)

    errors, all_rows, _ = validate_all(batch_dir)

    if errors:
        print(f"[AGGREGATE] FAIL: {len(errors)} validation errors:")
        for e in errors[:30]:
            for line in str(e).split("\n"):
                print(f"  {line}")
        if len(errors) > 30:
            print(f"  ... and {len(errors) - 30} more")
        sys.exit(1)

    # Protocol counts (post-validation summary)
    proto_counts = Counter(r["protocol"] for r in all_rows)
    for p in EXPECTED_PROTOCOLS:
        if proto_counts[p] != 80:
            print(f"[AGGREGATE] FAIL: {p} has {proto_counts[p]} rows, expected 80")
            sys.exit(1)

    # Atomic publish
    tmp_path = str(output_path) + ".tmp"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(all_rows[0].keys())

    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, str(output_path))

    sha = hashlib.sha256(open(str(output_path), "rb").read()).hexdigest()
    commits = set(r.get("git_commit", "") for r in all_rows)
    print(f"[AGGREGATE] OK: {len(all_rows)} rows published")
    print(f"[AGGREGATE] Output: {output_path}")
    print(f"[AGGREGATE] SHA-256: {sha}")
    print(f"[AGGREGATE] Protocols: {dict(proto_counts)}")
    print(f"[AGGREGATE] Commit: {list(commits)[0]}")


if __name__ == "__main__":
    main()
