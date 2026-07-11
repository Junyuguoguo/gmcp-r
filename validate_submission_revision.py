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


def parse_bool(value) -> bool:
    """Parse CSV boolean values without treating bool('False') as true."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes", "y"}


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
        attacks = [
            row for row in prows
            if row.get("attack_type") != "none"
            and parse_bool(row.get("attack_applicable"))
            and parse_bool(row.get("attack_injected"))
            and parse_bool(row.get("attack_packet_sent"))
        ]

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
            if parse_bool(r.get("attack_packet_rejected"))
        )
        false_accept = sum(
            1 for r in attacks
            if parse_bool(r.get("attack_packet_accepted"))
        )
        if attacks and detected + false_accept != len(attacks):
            raise ValueError(
                f"{protocol}: detected ({detected}) + false_accept ({false_accept}) "
                f"!= attack_count ({len(attacks)})"
            )
        detection_rate = detected / len(attacks) * 100 if attacks else 0
        false_accept_rate = false_accept / len(attacks) * 100 if attacks else 0

        summaries[protocol] = {
            "normal_throughput": round(normal_throughput, 2),
            "normal_rtt": round(normal_rtt, 3),
            "attack_detection_rate": round(detection_rate, 3),
            "false_accept_rate": round(false_accept_rate, 3),
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
    mode: str = "smoke",
) -> Tuple[bool, List[str]]:
    """
    Validate all submission revision artifacts.

    Returns (passed, violations).
    """
    violations: List[str] = []

    # 1. Manifest exists and hashes match
    manifest_path = os.path.join(output_root, "manifest.json")
    if not os.path.isfile(manifest_path):
        if mode == "release":
            violations.append("manifest.json not found")
    elif os.path.isfile(manifest_path):
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
    elif mode == "release":
        violations.append("required CSV missing or empty: recovery_window_experiment.csv")

    # 3. Validate checkpoint cost CSV
    cc_path = os.path.join(output_root, "checkpoint_cost_comparison.csv")
    cc_rows = read_csv(cc_path)
    if cc_rows:
        violations.extend(_validate_checkpoint_cost(cc_rows, expected_repeats))
    elif mode == "release":
        violations.append("required CSV missing or empty: checkpoint_cost_comparison.csv")

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
    elif mode == "release":
        violations.append("required CSV missing or empty: baseline_comparison.csv")

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
        "ticket_seq", "client_seq", "server_seq", "recovery_floor", "ticket_last_seq",
        "server_last_seq_before", "server_last_seq_after",
        "server_last_mem_before", "server_last_mem_after",
        "request_auth_ok", "response_auth_ok", "response_verify_reason",
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

    # repeat_id must be present and positive
    for row in rows:
        repeat_id = row.get("repeat_id", "")
        if not str(repeat_id).strip() or safe_int(repeat_id) <= 0:
            violations.append(
                f"recovery_window: repeat_id must be a positive integer "
                f"(scenario={row.get('scenario')}, repeat={repeat_id!r})"
            )
            break

    # All request/response auth and nonce binding must be True
    for row in rows:
        if not parse_bool(row.get("request_auth_ok", "")):
            violations.append(
                f"request_auth_ok should be True "
                f"(scenario={row.get('scenario')}, repeat={row.get('repeat_id')})"
            )
            break
        if not parse_bool(row.get("response_auth_ok", "")):
            violations.append(
                f"response_auth_ok should be True "
                f"(scenario={row.get('scenario')}, repeat={row.get('repeat_id')})"
            )
            break
        if not parse_bool(row.get("nonce_match", "")):
            violations.append(
                f"nonce_match should be True "
                f"(scenario={row.get('scenario')}, repeat={row.get('repeat_id')})"
            )
            break

    # Below-floor invariants
    for row in rows:
        if row.get("scenario") == "below_floor":
            context = (
                f"below_floor k={row.get('checkpoint_interval')} "
                f"p={row.get('payload_size')} repeat={row.get('repeat_id')}"
            )
            if parse_bool(row.get("success", "")):
                violations.append(f"{context}: below_floor should be rejected")
            if not parse_bool(row.get("state_unchanged", "")):
                violations.append(f"{context}: below_floor should leave state unchanged")
            if row.get("server_last_seq_before") != row.get("server_last_seq_after"):
                violations.append(f"{context}: server sequence changed on reject")
            if row.get("server_last_mem_before") != row.get("server_last_mem_after"):
                violations.append(f"{context}: server memory changed on reject")
            # recovery_floor must exceed ticket_last_seq (ticket is below the floor)
            rf = safe_int(row.get("recovery_floor", 0))
            tl = safe_int(row.get("ticket_last_seq", 0))
            if rf > 0 and tl > 0 and rf <= tl:
                violations.append(
                    f"{context}: recovery_floor ({rf}) must be > ticket_last_seq ({tl})"
                )
            # reason must NOT be "ok" — must contain rollback/below floor/recovery floor
            reason = row.get("reason", "").lower()
            valid_reason = any(
                needle in reason
                for needle in ("rollback", "below floor", "recovery floor", "older than required")
            )
            if not reason or reason == "ok" or not valid_reason:
                violations.append(
                    f"{context}: reason must describe rollback/below floor/recovery floor"
                )

    # Race invariants
    for row in race:
        winners = safe_int(row.get("race_winner_count"))
        if winners != 1:
            violations.append(f"nonce_race should have exactly 1 winner, got {winners}")
            break

    return violations


def _validate_checkpoint_cost(rows, expected_repeats):
    """Validate checkpoint cost CSV contracts."""
    violations = []

    required = {
        "protocol", "n", "k", "offset", "repeat_id",
        "replay_count", "target_seq", "target_state_match",
        "checkpoint_auth_ok", "record_auth_ok", "chain_continuity_ok",
        "payload_hash_ok", "stored_mem_ok", "recovery_valid", "failure_reason",
        "records_scanned", "records_replayed", "physical_bytes_read",
        "logical_bytes_replayed", "seek_offset",
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
    for row in rows:
        protocol = row.get("protocol")
        if not parse_bool(row.get("target_state_match")):
            continue
        if not parse_bool(row.get("recovery_valid")):
            continue
        if row.get("failure_reason"):
            violations.append(f"checkpoint_cost: success row has failure_reason={row.get('failure_reason')}")
            break
        if safe_int(row.get("physical_bytes_read")) <= 0:
            violations.append("checkpoint_cost: physical_bytes_read must be positive")
            break
        if safe_int(row.get("physical_bytes_read")) != safe_int(row.get("logical_bytes_replayed")):
            violations.append("checkpoint_cost: physical_bytes_read != logical_bytes_replayed")
            break
        if protocol == "gmcp_r":
            offset = safe_int(row.get("offset"))
            if safe_int(row.get("records_scanned")) != offset:
                violations.append("checkpoint_cost: gmcp_r records_scanned != offset")
                break
            if safe_int(row.get("records_replayed")) != offset:
                violations.append("checkpoint_cost: gmcp_r records_replayed != offset")
                break
            if safe_int(row.get("replay_count")) != offset:
                violations.append("checkpoint_cost: gmcp_r replay_count != offset")
                break
            if safe_int(row.get("seek_offset")) <= 0:
                violations.append("checkpoint_cost: gmcp_r seek_offset must be > 0")
                break
            for field in ("checkpoint_auth_ok", "record_auth_ok", "chain_continuity_ok", "payload_hash_ok", "stored_mem_ok"):
                if not parse_bool(row.get(field)):
                    violations.append(f"checkpoint_cost: gmcp_r {field} should be True")
                    break
        elif protocol == "authenticated_hash_chain":
            target_seq = safe_int(row.get("target_seq"))
            if safe_int(row.get("records_scanned")) != target_seq:
                violations.append("checkpoint_cost: auth chain records_scanned != target_seq")
                break
            if safe_int(row.get("records_replayed")) != target_seq:
                violations.append("checkpoint_cost: auth chain records_replayed != target_seq")
                break
            if safe_int(row.get("replay_count")) != target_seq:
                violations.append("checkpoint_cost: auth chain replay_count != target_seq")
                break
            if safe_int(row.get("seek_offset")) != 0:
                violations.append("checkpoint_cost: auth chain seek_offset must be 0")
                break

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

    # Row count check — deterministic formula:
    # for each (n, k): offsets = {1, k//2, k-1}; count += len(offsets) * 2 * repeats
    if expected_repeats > 0 and len(expected_combos) > 0:
        total_count = 0
        for (n_str, k_str) in expected_combos:
            k_val = safe_int(k_str)
            offsets_set = {1, k_val // 2, k_val - 1}
            total_count += len(offsets_set) * 2 * expected_repeats
        if total_count == 2160 and len(rows) != 2160:
            violations.append(f"checkpoint_cost: expected 2160 rows, got {len(rows)}")
        elif total_count != 2160 and len(rows) != total_count:
            violations.append(f"checkpoint_cost: expected {total_count} rows, got {len(rows)}")

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

    required = {
        "protocol", "attack_type", "message_count", "payload_size", "repeat_id",
        "attack_applicable", "attack_injected", "sent_count", "accepted_count",
        "rejected_count", "timeout_count", "error_count",
        "attack_packet_seq", "attack_packet_sent", "attack_packet_accepted",
        "attack_packet_rejected", "attack_packet_reason",
        "attack_packet_reason_class", "attack_expected_reason",
        "attack_reason_match", "post_attack_resynchronized", "retry_sent",
        "retry_accepted", "run_valid", "failure_reason",
    }
    if rows:
        missing = required - set(rows[0].keys())
        if missing:
            violations.append(f"baseline CSV missing columns: {missing}")
            return violations

    # Total row count check (full run only)
    if expected_repeats == 30:
        if len(rows) != 7200:
            violations.append(f"baseline: expected 7200 rows, got {len(rows)}")

    # Normal rows: attack_type == "none"
    normal = [r for r in rows if r.get("attack_type") == "none"]
    if expected_repeats == 30 and len(normal) != 900:
        violations.append(f"baseline: expected 900 normal rows, got {len(normal)}")

    keys = [
        (r.get("protocol"), r.get("attack_type"), r.get("message_count"),
         r.get("payload_size"), r.get("repeat_id"))
        for r in rows
    ]
    if len(keys) != len(set(keys)):
        violations.append("baseline: duplicate composite keys")

    # All rows must have consistent counts and clean execution
    for row in rows:
        sent = safe_int(row.get("sent_count"))
        accepted = safe_int(row.get("accepted_count"))
        rejected = safe_int(row.get("rejected_count"))
        timeout = safe_int(row.get("timeout_count"))
        error = safe_int(row.get("error_count"))
        if sent != accepted + rejected + timeout + error:
            violations.append(
                f"baseline: sent_count mismatch protocol={row.get('protocol')} "
                f"attack={row.get('attack_type')} repeat={row.get('repeat_id')}"
            )
            break
        if timeout != 0 or error != 0:
            violations.append(
                f"baseline: timeout/error in row "
                f"(protocol={row.get('protocol')}, attack={row.get('attack_type')}, "
                f"repeat={row.get('repeat_id')}, timeout={timeout}, error={error})"
            )
            break
        if not parse_bool(row.get("run_valid")):
            violations.append("baseline: run_valid should be True")
            break
        if row.get("failure_reason"):
            violations.append("baseline: failure_reason should be empty")
            break

    # All normal rows must be 100% successful
    for row in normal:
        message_count = safe_int(row.get("message_count"))
        if parse_bool(row.get("attack_injected")) or parse_bool(row.get("attack_packet_sent")):
            violations.append("baseline: normal row must not inject attack")
            break
        if safe_int(row.get("accepted_count")) != message_count:
            violations.append("baseline: normal accepted_count must equal message_count")
            break
        if safe_int(row.get("rejected_count")) != 0 or safe_int(row.get("sent_count")) != message_count:
            violations.append("baseline: normal sent/rejected counts invalid")
            break

    # Attack audit invariants
    for row in rows:
        attack = row.get("attack_type", "")
        if attack == "none":
            continue

        applicable = parse_bool(row.get("attack_applicable"))
        injected = parse_bool(row.get("attack_injected"))
        sent_attack = parse_bool(row.get("attack_packet_sent"))
        accepted_attack = parse_bool(row.get("attack_packet_accepted"))
        rejected_attack = parse_bool(row.get("attack_packet_rejected"))
        message_count = safe_int(row.get("message_count"))

        if applicable:
            if not injected or not sent_attack:
                violations.append(
                    f"baseline: applicable attack not injected "
                    f"(protocol={row.get('protocol')}, attack={attack}, repeat={row.get('repeat_id')})"
                )
                break
            if accepted_attack == rejected_attack:
                violations.append("baseline: attack packet must be accepted XOR rejected")
                break
            if rejected_attack:
                if safe_int(row.get("rejected_count")) < 1:
                    violations.append("baseline: rejected attack row must count a rejection")
                    break
                if not parse_bool(row.get("retry_sent")) or not parse_bool(row.get("retry_accepted")):
                    violations.append("baseline: rejected attack must send and accept clean retry")
                    break
                if not parse_bool(row.get("post_attack_resynchronized")):
                    violations.append("baseline: rejected attack must be post_attack_resynchronized")
                    break
                if safe_int(row.get("accepted_count")) != message_count:
                    violations.append("baseline: rejected attack accepted_count must equal message_count")
                    break
                if safe_int(row.get("sent_count")) != message_count + 1:
                    violations.append("baseline: rejected attack sent_count must equal message_count + 1")
                    break
            if accepted_attack:
                if safe_int(row.get("sent_count")) != message_count:
                    violations.append("baseline: accepted attack sent_count must equal message_count")
                    break
        else:
            if injected or sent_attack or accepted_attack or rejected_attack:
                violations.append("baseline: N/A attack should not be injected or sent")
                break
            if safe_int(row.get("accepted_count")) != message_count:
                violations.append("baseline: N/A row accepted_count must equal message_count")
                break
            if safe_int(row.get("rejected_count")) != 0 or safe_int(row.get("sent_count")) != message_count:
                violations.append("baseline: N/A row sent/rejected counts invalid")
                break

        if attack == "cross_session_valid_mac":
            reason = row.get("attack_packet_reason", "")
            if not rejected_attack or "connection session mismatch" not in reason:
                violations.append("baseline: cross_session_valid_mac reason must be connection session mismatch")
                break
            if not parse_bool(row.get("attack_reason_match")):
                violations.append("baseline: cross_session_valid_mac attack_reason_match should be True")
                break
        if attack == "cross_epoch_valid_mac":
            reason = row.get("attack_packet_reason", "")
            if not rejected_attack or "connection epoch mismatch" not in reason:
                violations.append("baseline: cross_epoch_valid_mac reason must be connection epoch mismatch")
                break
            if not parse_bool(row.get("attack_reason_match")):
                violations.append("baseline: cross_epoch_valid_mac attack_reason_match should be True")
                break

    # Denominator sanity: applicable+injected+sent attacks must be accepted or rejected.
    attacks = [
        row for row in rows
        if row.get("attack_type") != "none"
        and parse_bool(row.get("attack_applicable"))
        and parse_bool(row.get("attack_injected"))
        and parse_bool(row.get("attack_packet_sent"))
    ]
    detected_count = sum(1 for row in attacks if parse_bool(row.get("attack_packet_rejected")))
    false_accept_count = sum(1 for row in attacks if parse_bool(row.get("attack_packet_accepted")))
    if attacks and detected_count + false_accept_count != len(attacks):
        violations.append("baseline: detected + false accepted must equal applicable injected count")

    # N/A attack semantics
    na_protocols = {"seq_mac", "ticket_only"}
    for row in rows:
        proto = row.get("protocol", "")
        attack = row.get("attack_type", "")
        injected = parse_bool(row.get("attack_injected"))
        sent_attack = parse_bool(row.get("attack_packet_sent"))
        if proto in na_protocols and attack in {"prev_mem", "forged_prev_mem_valid_mac"} and (injected or sent_attack):
            violations.append(
                f"N/A attack should not be injected for {proto}/{attack}"
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
    parser.add_argument(
        "--mode",
        choices=["smoke", "release"],
        default="smoke",
        help="Validation strictness. release requires all core artifacts.",
    )
    args = parser.parse_args()

    passed, violations = validate_all(args.output_root, args.expected_repeats, args.mode)

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
