#!/usr/bin/env python3
"""
Strict aggregator for cross-host formal experiment batches.

Reads 20 successful batch CSVs (cross_host_batch_rNN.csv) and produces
the final cross_host_results.csv via atomic publish.

Usage:
    python3 aggregate_cross_host_batches.py \
        --batch-dir /path/to/batches \
        --output results/cross_host/cross_host_results.csv
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter
from pathlib import Path

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

    if len(rows) != ROWS_PER_BATCH:
        errors.append(f"{batch_path.name}: expected {ROWS_PER_BATCH} rows, got {len(rows)}")

    for i, r in enumerate(rows, 1):
        ctx = f"{batch_path.name} row {i}"

        # repeat_id must match
        rid = int(r.get("repeat_id", -1))
        if rid != repeat_id:
            errors.append(f"{ctx}: repeat_id={rid}, expected {repeat_id}")

        # run_valid must be True
        if r.get("run_valid") not in ("True", "true", True):
            errors.append(f"{ctx}: run_valid={r.get('run_valid')}")

        # accepted == message_count
        if int(r.get("accepted_count", -1)) != int(r.get("message_count", -2)):
            errors.append(f"{ctx}: accepted != message_count")

        # rejected/timeout/error = 0
        for field in ("rejected_count", "timeout_count", "error_count"):
            if int(r.get(field, -1)) != 0:
                errors.append(f"{ctx}: {field}={r.get(field)}")

        # commit 40 chars
        commit = r.get("git_commit", "")
        if len(commit) != 40:
            errors.append(f"{ctx}: git_commit length {len(commit)} != 40")

        # dirty = false
        if r.get("git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: git_dirty={r.get('git_dirty')}")

        # server dirty = false
        if r.get("server_git_dirty") not in ("false", "False", False):
            errors.append(f"{ctx}: server_git_dirty={r.get('server_git_dirty')}")

        # protocol-specific state match
        proto = r.get("protocol", "")
        if proto == "gmcp_r" and r.get("memory_match") not in ("True", "true", True):
            errors.append(f"{ctx}: gmcp_r memory_match={r.get('memory_match')}")
        if proto in ("hash_chain", "authenticated_hash_chain") and r.get("hash_match") not in ("True", "true", True):
            errors.append(f"{ctx}: {proto} hash_match={r.get('hash_match')}")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Aggregate cross-host formal batches")
    parser.add_argument("--batch-dir", required=True, help="Directory containing batch CSVs")
    parser.add_argument("--output", required=True, help="Output path for cross_host_results.csv")
    args = parser.parse_args()

    batch_dir = Path(args.batch_dir)
    output_path = Path(args.output)

    # 1. Find all batch files
    batch_files = sorted(batch_dir.glob("cross_host_batch_r*.csv"))
    batch_files = [f for f in batch_files if not f.name.endswith(".failed.csv")]

    if len(batch_files) != 20:
        print(f"[AGGREGATE] FAIL: expected 20 batch files, found {len(batch_files)}")
        for f in batch_files:
            print(f"  {f.name}")
        sys.exit(1)

    # 2. Validate repeat_ids
    repeat_ids = set()
    for f in batch_files:
        try:
            rid = int(f.stem.split("_r")[1])
            repeat_ids.add(rid)
        except (IndexError, ValueError):
            print(f"[AGGREGATE] FAIL: cannot parse repeat_id from {f.name}")
            sys.exit(1)

    if repeat_ids != EXPECTED_REPEAT_IDS:
        missing = EXPECTED_REPEAT_IDS - repeat_ids
        extra = repeat_ids - EXPECTED_REPEAT_IDS
        print(f"[AGGREGATE] FAIL: repeat_id mismatch. missing={missing}, extra={extra}")
        sys.exit(1)

    # 3. Load and validate all batches
    all_rows = []
    batch_errors = []

    for f in batch_files:
        rid = int(f.stem.split("_r")[1])
        rows = load_batch(f)
        errors = validate_batch(rows, rid, f)
        if errors:
            batch_errors.extend(errors)
        all_rows.extend(rows)

    if batch_errors:
        print(f"[AGGREGATE] FAIL: {len(batch_errors)} validation errors:")
        for e in batch_errors[:20]:
            print(f"  {e}")
        if len(batch_errors) > 20:
            print(f"  ... and {len(batch_errors) - 20} more")
        sys.exit(1)

    # 4. Cross-batch validation
    if len(all_rows) != 400:
        print(f"[AGGREGATE] FAIL: expected 400 total rows, got {len(all_rows)}")
        sys.exit(1)

    # 5. Exact configuration count
    exact = Counter(
        (r["protocol"], int(r["message_count"]), int(r["payload_size"]))
        for r in all_rows
    )
    if set(exact) != EXPECTED_CONFIGS:
        print(f"[AGGREGATE] FAIL: configuration mismatch")
        sys.exit(1)

    for key in sorted(EXPECTED_CONFIGS):
        if exact[key] != 20:
            print(f"[AGGREGATE] FAIL: {key} has {exact[key]} rows, expected 20")
            sys.exit(1)

    # 6. Commit consistency
    commits = set(r.get("git_commit", "") for r in all_rows)
    if len(commits) != 1:
        print(f"[AGGREGATE] FAIL: {len(commits)} different client commits")
        sys.exit(1)

    server_commits = set(r.get("server_git_commit", "") for r in all_rows)
    if len(server_commits) != 1:
        print(f"[AGGREGATE] FAIL: {len(server_commits)} different server commits")
        sys.exit(1)

    # 7. Unique session_ids
    session_ids = [r.get("session_id", "") for r in all_rows]
    if len(session_ids) != len(set(session_ids)):
        dups = len(session_ids) - len(set(session_ids))
        print(f"[AGGREGATE] FAIL: {dups} duplicate session_ids")
        sys.exit(1)

    # 8. Protocol counts
    proto_counts = Counter(r["protocol"] for r in all_rows)
    for p in EXPECTED_PROTOCOLS:
        if proto_counts[p] != 80:
            print(f"[AGGREGATE] FAIL: {p} has {proto_counts[p]} rows, expected 80")
            sys.exit(1)

    # 9. Atomic publish
    tmp_path = str(output_path) + ".tmp"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Get fieldnames from first batch
    fieldnames = list(all_rows[0].keys())

    with open(tmp_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, str(output_path))

    sha = hashlib.sha256(open(str(output_path), "rb").read()).hexdigest()
    print(f"[AGGREGATE] OK: {len(all_rows)} rows published")
    print(f"[AGGREGATE] Output: {output_path}")
    print(f"[AGGREGATE] SHA-256: {sha}")
    print(f"[AGGREGATE] Protocols: {dict(proto_counts)}")
    print(f"[AGGREGATE] Commit: {list(commits)[0]}")


if __name__ == "__main__":
    main()
