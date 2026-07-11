#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate_weak_network_artifact.py

Validate 05_weak_network.csv artifact integrity.

Checks:
  1. Exactly 150 rows
  2. Matrix complete: 3 protocols × 5 loss_rates × 5 delay_ms × 2 repeats
  3. Lossless control group (loss=0, delay=0) has 100% success_rate
  4. loss>0 rows have simulated_drop_count > 0
  5. success_rate consistent with accepted_logical_messages / logical_message_count
  6. run_seed non-empty (replaces old git_commit check)
  7. git_dirty == false (if column exists)
  8. Protocol-specific state consistency:
     - gmcp_r: state_match AND memory_match
     - hash_chain: state_match AND hash_match
     - seq_mac: state_match AND sequence_match
  9. run_valid == True (if column exists)

Exits nonzero with one line per violation.
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from gmcp.analysis.baseline_metrics import (
    EXPECTED_WEAK_NETWORK_MATRIX,
    EXPECTED_WEAK_NETWORK_ROW_COUNT,
)


def fail(errors: list) -> int:
    for err in errors:
        print(f"FAIL: {err}")
    return 1


def warn(msgs: list) -> None:
    for msg in msgs:
        print(f"WARN: {msg}")


def read_csv_rows(path: str) -> list:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# Protocol-specific consistency columns
PROTOCOL_MATCH_COLS = {
    "gmcp_r": ["state_match", "memory_match"],
    "hash_chain": ["state_match", "hash_match"],
    "seq_mac": ["state_match", "sequence_match"],
}


def validate() -> int:
    errors = []
    warnings = []
    root = Path(__file__).resolve().parent
    csv_path = root / "paper_data" / "05_weak_network.csv"

    if not csv_path.is_file():
        return fail(["paper_data/05_weak_network.csv not found"])

    try:
        rows = read_csv_rows(str(csv_path))
    except Exception as e:
        return fail([f"CSV parse error: {e}"])

    # -------------------------------------------------------------------
    # 1. Row count = 150
    # -------------------------------------------------------------------
    if len(rows) != EXPECTED_WEAK_NETWORK_ROW_COUNT:
        errors.append(
            f"05_weak_network.csv: expected {EXPECTED_WEAK_NETWORK_ROW_COUNT} rows, "
            f"got {len(rows)}"
        )

    # -------------------------------------------------------------------
    # 2. Matrix completeness: 3 protocols × 5 loss × 5 delay × 2 repeats
    # -------------------------------------------------------------------
    expected_protos = set(EXPECTED_WEAK_NETWORK_MATRIX["protocols"])
    expected_losses = set(EXPECTED_WEAK_NETWORK_MATRIX["loss_rates"])
    expected_delays = set(EXPECTED_WEAK_NETWORK_MATRIX["delay_ms"])
    expected_repeats = set(EXPECTED_WEAK_NETWORK_MATRIX["repeats"])

    actual_combos = set()
    for r in rows:
        try:
            combo = (
                r["protocol"],
                int(float(r["loss_rate"])),
                int(float(r["delay_ms"])),
                int(float(r["repeat_id"])),
            )
            actual_combos.add(combo)
        except (KeyError, ValueError) as e:
            errors.append(f"Row parse error: {e}")

    # Build expected combos
    expected_combos = set()
    for p in expected_protos:
        for l in expected_losses:
            for d in expected_delays:
                for rp in expected_repeats:
                    expected_combos.add((p, l, d, rp))

    missing = expected_combos - actual_combos
    extra = actual_combos - expected_combos

    if missing:
        for m in sorted(missing):
            errors.append(f"Missing matrix entry: protocol={m[0]}, loss={m[1]}, delay={m[2]}, repeat={m[3]}")

    if extra:
        for e in sorted(extra):
            warnings.append(f"Extra matrix entry: protocol={e[0]}, loss={e[1]}, delay={e[2]}, repeat={e[3]}")

    # Check protocol set
    actual_protos = set(r["protocol"] for r in rows)
    if actual_protos != expected_protos:
        errors.append(f"Protocol mismatch: expected {sorted(expected_protos)}, got {sorted(actual_protos)}")

    # -------------------------------------------------------------------
    # 3. Lossless control group: loss=0, delay=0 → 100% success
    # -------------------------------------------------------------------
    control = [r for r in rows if int(float(r["loss_rate"])) == 0 and int(float(r["delay_ms"])) == 0]
    for r in control:
        sr = float(r["success_rate"])
        if abs(sr - 100.0) > 0.01:
            errors.append(
                f"Control group failure: protocol={r['protocol']}, repeat={r['repeat_id']}, "
                f"success_rate={sr}% (expected 100%)"
            )

    # -------------------------------------------------------------------
    # 4. loss>0 → simulated_drop_count > 0
    # -------------------------------------------------------------------
    lossy = [r for r in rows if int(float(r["loss_rate"])) > 0]
    zero_drop = [r for r in lossy if int(float(r.get("simulated_drop_count", 0))) == 0]
    if zero_drop:
        # At least some rows with loss>0 should have drops; check per-config
        lossy_configs = {}
        for r in lossy:
            key = (r["protocol"], r["loss_rate"], r["delay_ms"])
            lossy_configs.setdefault(key, []).append(r)

        no_drop_configs = []
        for key, config_rows in lossy_configs.items():
            total_drops = sum(int(float(r.get("simulated_drop_count", 0))) for r in config_rows)
            if total_drops == 0:
                no_drop_configs.append(key)

        if no_drop_configs:
            for cfg in sorted(no_drop_configs):
                errors.append(
                    f"loss>0 but no drops: protocol={cfg[0]}, loss={cfg[1]}, delay={cfg[2]}"
                )

    # -------------------------------------------------------------------
    # 5. success_rate consistency: accepted_logical_messages / logical_message_count * 100
    # -------------------------------------------------------------------
    for r in rows:
        try:
            accepted = int(float(r["accepted_logical_messages"]))
            msg_count = int(float(r["logical_message_count"]))
            sr = float(r["success_rate"])
            expected_sr = round(accepted / msg_count * 100, 2) if msg_count > 0 else 0
            if abs(sr - expected_sr) > 0.1:
                errors.append(
                    f"success_rate mismatch: protocol={r['protocol']}, "
                    f"loss={r['loss_rate']}, delay={r['delay_ms']}, repeat={r['repeat_id']}: "
                    f"got {sr}, expected {expected_sr}"
                )
        except (KeyError, ValueError) as e:
            errors.append(f"Row validation error: {e}")

    # -------------------------------------------------------------------
    # 6. run_seed non-empty (replaces old git_commit check)
    # -------------------------------------------------------------------
    for r in rows:
        rs = r.get("run_seed", "").strip()
        if not rs:
            errors.append(
                f"Empty run_seed: protocol={r['protocol']}, loss={r['loss_rate']}, "
                f"delay={r['delay_ms']}, repeat={r['repeat_id']}"
            )

    # -------------------------------------------------------------------
    # 7. git_dirty == false (if column exists)
    # -------------------------------------------------------------------
    if "git_dirty" in rows[0]:
        dirty_rows = [r for r in rows if r.get("git_dirty", "").strip().lower() not in ("false", "0", "")]
        if dirty_rows:
            for r in dirty_rows:
                errors.append(
                    f"git_dirty is not false: protocol={r['protocol']}, "
                    f"loss={r['loss_rate']}, delay={r['delay_ms']}"
                )
    else:
        errors.append("Column 'git_dirty' not present; required for formal validation")

    # -------------------------------------------------------------------
    # 8. Protocol-specific state consistency
    # -------------------------------------------------------------------
    for r in rows:
        proto = r.get("protocol", "")
        match_cols = PROTOCOL_MATCH_COLS.get(proto)
        if match_cols is None:
            errors.append(f"Unknown protocol for state check: {proto}")
            continue
        for col in match_cols:
            if col in r:
                val = str(r[col]).strip().lower()
                if val not in ("true", "1"):
                    errors.append(
                        f"{col} is not true: protocol={proto}, "
                        f"loss={r['loss_rate']}, delay={r['delay_ms']}, repeat={r['repeat_id']}"
                    )
            else:
                warnings.append(f"Column '{col}' not present for protocol {proto}; skipping")

    # -------------------------------------------------------------------
    # 9. run_valid == True (if column exists)
    # -------------------------------------------------------------------
    if "run_valid" in rows[0]:
        invalid = [r for r in rows if str(r.get("run_valid", "")).strip().lower() not in ("true", "1")]
        if invalid:
            for r in invalid:
                errors.append(
                    f"run_valid is not true: protocol={r['protocol']}, "
                    f"loss={r['loss_rate']}, delay={r['delay_ms']}, repeat={r['repeat_id']}"
                )
    else:
        errors.append("Column 'run_valid' not present; required for formal validation")

    # -------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------
    warn(warnings)

    if errors:
        return fail(errors)

    print("PASS: All weak-network artifact checks passed.")
    print(f"  Rows: {len(rows)}, Protocols: {sorted(actual_protos)}")
    print(f"  Matrix entries: {len(actual_combos)}/{len(expected_combos)}")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
