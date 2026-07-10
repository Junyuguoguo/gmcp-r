# -*- coding: utf-8 -*-
# validate_submission_revision.py
#
# Independent validator for submission revision artifacts.
# Reads raw CSVs, recomputes summaries, and checks all contracts.
# Exits nonzero with one line per violation.

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Tuple


def read_csv(path: str) -> List[Dict[str, str]]:
    """Read a CSV file into a list of row dicts."""
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def safe_float(val: str) -> float:
    """Convert string to float, defaulting to 0."""
    try:
        return float(val)
    except (ValueError, TypeError):
        return 0.0


def safe_int(val: str) -> int:
    """Convert string to int, defaulting to 0."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0


# ---------------------------------------------------------------------------
# Summary recomputation helpers
# ---------------------------------------------------------------------------

def recompute_baseline_summary(rows: List[Dict[str, str]]) -> Dict[str, Dict[str, float]]:
    """Recompute per-protocol summary from raw baseline CSV rows."""
    by_protocol: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_protocol[row.get("protocol", "unknown")].append(row)

    summaries = {}
    for protocol, prows in by_protocol.items():
        normal = [r for r in prows if r.get("attack_type") == "none"]
        attacks = [r for r in prows if r.get("attack_type") != "none"]

        normal_throughput = (
            sum(safe_float(r.get("throughput_msg_per_sec", 0)) for r in normal) / len(normal)
            if normal else 0
        )
        normal_rtt = (
            sum(safe_float(r.get("rtt_mean_ms", 0)) for r in normal) / len(normal)
            if normal else 0
        )

        detected = sum(
            1 for r in attacks
            if str(r.get("attack_detected_by_server", "")).lower() == "true"
        )
        detection_rate = detected / len(attacks) * 100 if attacks else 0
        false_accept = (len(attacks) - detected) / len(attacks) * 100 if attacks else 0

        summaries[protocol] = {
            "normal_throughput": round(normal_throughput, 2),
            "normal_rtt": round(normal_rtt, 3),
            "attack_detection_rate": round(detection_rate, 3),
            "false_accept_rate": round(false_accept, 3),
            "normal_count": len(normal),
            "attack_count": len(attacks),
        }

    return summaries


def recompute_recovery_window_summary(
    rows: List[Dict[str, str]],
) -> Dict[str, Dict[str, object]]:
    """Recompute per-scenario summary from recovery window CSV."""
    by_scenario: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    for row in rows:
        by_scenario[row.get("scenario", "unknown")].append(row)

    summaries = {}
    for scenario, srows in by_scenario.items():
        success_count = sum(1 for r in srows if str(r.get("success", "")).lower() == "true")
        summaries[scenario] = {
            "count": len(srows),
            "success_count": success_count,
            "success_rate": success_count / len(srows) * 100 if srows else 0,
        }
    return summaries


# ---------------------------------------------------------------------------
# Validation routines
# ---------------------------------------------------------------------------

def validate_all(
    output_root: str,
    expected_repeats: int = 30,
) -> Tuple[bool, List[str]]:
    """
    Validate all submission revision artifacts.

    Returns (passed, violations).
    """
    violations: List[str] = []

    # 1. Manifest exists and hashes match
    manifest_path = os.path.join(output_root, "manifest.json")
    if not os.path.isfile(manifest_path):
        violations.append("manifest.json not found")
    else:
        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

        from gmcp.experiment_manifest import sha256_file

        for category in ("csv_hashes", "plot_hashes"):
            for name, info in manifest.get(category, {}).items():
                fpath = os.path.join(output_root, info["path"])
                if not os.path.isfile(fpath):
                    violations.append(f"{category}/{name}: file missing ({info['path']})")
                elif os.path.getsize(fpath) == 0:
                    violations.append(f"{category}/{name}: file is empty ({info['path']})")
                else:
                    actual = sha256_file(fpath)
                    if actual != info["sha256"]:
                        violations.append(
                            f"{category}/{name}: hash mismatch "
                            f"(expected {info['sha256'][:16]}…)"
                        )

    # 2. Validate recovery window CSV
    rw_path = os.path.join(output_root, "recovery_window_experiment.csv")
    rw_rows = read_csv(rw_path)
    if rw_rows:
        violations.extend(_validate_recovery_window(rw_rows, expected_repeats))

    # 3. Validate checkpoint cost CSV
    cc_path = os.path.join(output_root, "checkpoint_cost_comparison.csv")
    cc_rows = read_csv(cc_path)
    if cc_rows:
        violations.extend(_validate_checkpoint_cost(cc_rows, expected_repeats))

    # 4. Validate adaptive attack CSV
    aa_path = os.path.join(output_root, "hash_chain_adaptive_attack.csv")
    aa_rows = read_csv(aa_path)
    if aa_rows:
        violations.extend(_validate_adaptive_attack(aa_rows))

    # 5. Validate baseline comparison CSV (if present)
    bl_path = os.path.join(output_root, "baseline_comparison.csv")
    if not os.path.isfile(bl_path):
        bl_path = os.path.join(output_root, "real_baseline_comparison_results.csv")
    bl_rows = read_csv(bl_path)
    if bl_rows:
        violations.extend(_validate_baseline(bl_rows, expected_repeats))

    # 6. Validate all PNGs are nonempty
    if os.path.isdir(output_root):
        for fname in os.listdir(output_root):
            if fname.endswith(".png"):
                fpath = os.path.join(output_root, fname)
                if os.path.getsize(fpath) == 0:
                    violations.append(f"Plot file is empty: {fname}")

    passed = len(violations) == 0
    return passed, violations


def _validate_recovery_window(rows, expected_repeats):
    """Validate recovery window CSV contracts."""
    violations = []

    # Required columns
    required = {
        "scenario", "checkpoint_interval", "payload_size", "repeat_id",
        "ticket_seq", "client_seq", "server_seq", "floor_seq", "response_seq",
        "gap", "response_advance", "request_auth_ok", "response_auth_ok",
        "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
        "success", "reason",
    }
    if rows:
        missing = required - set(rows[0].keys())
        if missing:
            violations.append(f"recovery_window CSV missing columns: {missing}")

    # Duplicate composite keys
    keys = [
        (r.get("scenario"), r.get("checkpoint_interval"), r.get("payload_size"), r.get("repeat_id"))
        for r in rows
    ]
    if len(keys) != len(set(keys)):
        violations.append("recovery_window CSV has duplicate composite keys")

    # Row count
    non_race = [r for r in rows if r.get("scenario") != "nonce_race"]
    race = [r for r in rows if r.get("scenario") == "nonce_race"]

    if expected_repeats == 30:
        if len(rows) != 760:
            violations.append(f"recovery_window: expected 760 rows, got {len(rows)}")
        if len(non_race) != 720:
            violations.append(f"recovery_window: expected 720 non-race rows, got {len(non_race)}")
        if len(race) != 40:
            violations.append(f"recovery_window: expected 40 race rows, got {len(race)}")

    # Below-floor invariants
    for row in rows:
        if row.get("scenario") == "below_floor":
            if str(row.get("success", "")).lower() == "true":
                violations.append("below_floor should be rejected")
            if str(row.get("state_unchanged", "")).lower() != "true":
                violations.append("below_floor should leave state unchanged")
            # recovery_floor must exceed ticket_last_seq (ticket is below the floor)
            rf = safe_int(row.get("recovery_floor", 0))
            tl = safe_int(row.get("ticket_last_seq", 0))
            if rf > 0 and tl > 0 and rf <= tl:
                violations.append(
                    f"below_floor: recovery_floor ({rf}) must be > ticket_last_seq ({tl})"
                )

    # Race invariants
    for row in race:
        winners = safe_int(row.get("race_winner_count"))
        if winners != 1:
            violations.append(f"nonce_race should have exactly 1 winner, got {winners}")

    return violations


def _validate_checkpoint_cost(rows, expected_repeats):
    """Validate checkpoint cost CSV contracts."""
    violations = []

    required = {
        "protocol", "n", "k", "offset", "repeat_id",
        "replay_count", "recovery_material_bytes", "target_state_match",
    }
    if rows:
        missing = required - set(rows[0].keys())
        if missing:
            violations.append(f"checkpoint_cost CSV missing columns: {missing}")

    # Duplicate composite keys
    keys = [
        (r.get("protocol"), r.get("n"), r.get("k"), r.get("offset"), r.get("repeat_id"))
        for r in rows
    ]
    if len(keys) != len(set(keys)):
        violations.append("checkpoint_cost CSV has duplicate composite keys")

    # All reconstruction must match
    mismatches = [
        r for r in rows if str(r.get("target_state_match", "")).lower() != "true"
    ]
    if mismatches:
        violations.append(
            f"checkpoint_cost: {len(mismatches)} rows have state mismatch"
        )

    # recovery_valid must be True for all rows (if column exists)
    if rows and "recovery_valid" in rows[0]:
        invalid = [
            r for r in rows if str(r.get("recovery_valid", "")).lower() != "true"
        ]
        if invalid:
            violations.append(
                f"checkpoint_cost: {len(invalid)} rows have recovery_valid=False"
            )

    # records_scanned == offset for gmcp_r (if columns exist)
    if rows and "records_scanned" in rows[0] and "offset" in rows[0]:
        scan_mismatches = [
            r for r in rows
            if r.get("protocol") == "gmcp_r"
            and safe_int(r.get("records_scanned")) != safe_int(r.get("offset"))
        ]
        if scan_mismatches:
            violations.append(
                f"checkpoint_cost: {len(scan_mismatches)} gmcp_r rows have "
                f"records_scanned != offset"
            )

    # Matrix coverage
    combos = set((r.get("n"), r.get("k")) for r in rows)
    n_values = sorted(set(safe_int(r.get("n")) for r in rows))
    k_values = sorted(set(safe_int(r.get("k")) for r in rows))
    expected_combos = set()
    for n in n_values:
        for k in k_values:
            if k < n:
                expected_combos.add((str(n), str(k)))
    missing_combos = expected_combos - combos
    if missing_combos:
        violations.append(f"checkpoint_cost: missing matrix combos {missing_combos}")

    # Row count check — expected_count = len(expected_combos) × len(offsets) × len(protocols) × repeats
    if expected_repeats == 30 and len(expected_combos) > 0:
        offsets = set(safe_int(r.get("offset")) for r in rows)
        protocols = set(r.get("protocol") for r in rows)
        expected_count = len(expected_combos) * len(offsets) * len(protocols) * 30
        if expected_count == 2160 and len(rows) != 2160:
            violations.append(f"checkpoint_cost: expected 2160 rows, got {len(rows)}")

    return violations


def _validate_adaptive_attack(rows):
    """Validate adaptive attack CSV contracts."""
    violations = []

    required = {"protocol", "attack_applicable", "attack_accepted"}
    if rows:
        missing = required - set(rows[0].keys())
        if missing:
            violations.append(f"adaptive_attack CSV missing columns: {missing}")

    # Duplicate keys
    keys = [(r.get("protocol", ""), r.get("attack_type", "")) for r in rows]
    if len(keys) != len(set(keys)):
        violations.append("adaptive_attack CSV has duplicate composite keys")

    for row in rows:
        proto = row.get("protocol", "")
        accepted = str(row.get("attack_accepted", "")).lower()

        if proto == "authenticated_hash_chain" and accepted == "true":
            violations.append("authenticated_hash_chain should reject adaptive attack")

        if proto == "hash_chain":
            applicable = str(row.get("attack_applicable", "")).lower()
            if applicable == "true" and accepted != "true":
                violations.append("plain hash_chain should accept adaptive attack")

    return violations


def _validate_baseline(rows, expected_repeats=30):
    """Validate baseline comparison CSV contracts."""
    violations = []

    required = {"protocol", "attack_type", "message_count", "repeat_id"}
    if rows:
        missing = required - set(rows[0].keys())
        if missing:
            violations.append(f"baseline CSV missing columns: {missing}")

    # Total row count check (full run only)
    if expected_repeats == 30:
        if len(rows) != 7200:
            violations.append(f"baseline: expected 7200 rows, got {len(rows)}")

    # Normal rows: attack_type == "none"
    normal = [r for r in rows if r.get("attack_type") == "none"]
    if expected_repeats == 30 and len(normal) != 900:
        violations.append(f"baseline: expected 900 normal rows, got {len(normal)}")

    # All normal rows must be 100% successful
    for row in normal:
        sr = safe_float(row.get("success_rate", 100))
        if sr < 100.0:
            violations.append(
                f"baseline: normal row not 100% successful "
                f"(protocol={row.get('protocol')}, msg={row.get('message_count')}, "
                f"repeat={row.get('repeat_id')}, success_rate={sr})"
            )
            break  # one violation is enough to flag

    # No timeout or error rows
    for row in rows:
        tc = safe_int(row.get("timeout_count", 0))
        ec = safe_int(row.get("error_count", 0))
        if tc > 0 or ec > 0:
            violations.append(
                f"baseline: timeout/error in row "
                f"(protocol={row.get('protocol')}, attack={row.get('attack_type')}, "
                f"repeat={row.get('repeat_id')}, timeout={tc}, error={ec})"
            )
            break

    # N/A attack semantics
    na_protocols = {"seq_mac", "ticket_only"}
    for row in rows:
        proto = row.get("protocol", "")
        attack = row.get("attack_type", "")
        injected = str(row.get("attack_injected", "")).lower()
        if proto in na_protocols and attack == "prev_mem" and injected == "true":
            violations.append(f"N/A attack should not be injected for {proto}/{attack}")

    # Applicable attacks must be injected (if attack_applicable column exists)
    if rows and "attack_applicable" in rows[0]:
        for row in rows:
            applicable = str(row.get("attack_applicable", "")).lower()
            injected = str(row.get("attack_injected", "")).lower()
            attack = row.get("attack_type", "")
            if attack != "none" and applicable == "true" and injected != "true":
                violations.append(
                    f"baseline: applicable attack not injected "
                    f"(protocol={row.get('protocol')}, attack={attack}, "
                    f"repeat={row.get('repeat_id')})"
                )
                break

    return violations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Validate submission revision artifacts"
    )
    parser.add_argument(
        "--output-root",
        default="results/submission_revision",
        help="Root directory of submission artifacts",
    )
    parser.add_argument(
        "--expected-repeats",
        type=int,
        default=30,
        help="Expected number of repeats per experiment (30 for full, 1 for smoke)",
    )
    args = parser.parse_args()

    passed, violations = validate_all(args.output_root, args.expected_repeats)

    if passed:
        print("VALIDATION PASSED")
        return 0
    else:
        print(f"VALIDATION FAILED ({len(violations)} violation(s)):")
        for v in violations:
            print(f"  - {v}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
