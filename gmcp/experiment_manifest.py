# -*- coding: utf-8 -*-
# gmcp/experiment_manifest.py
#
# Manifest generation and validation for submission revision artifacts.
# Records protocol version, environment, timing, CSV hashes, and plot input hashes.

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


def sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_git_info(repo_dir: str) -> Dict[str, Any]:
    """Get git commit hash and dirty flag."""
    info: Dict[str, Any] = {"commit": "unknown", "dirty": False}
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=repo_dir,
        )
        if result.returncode == 0:
            info["commit"] = result.stdout.strip()
        result2 = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True, text=True, cwd=repo_dir,
        )
        if result2.returncode == 0:
            info["dirty"] = bool(result2.stdout.strip())
    except Exception:
        pass
    return info


def _get_dependencies() -> Dict[str, str]:
    """Get installed package versions for key dependencies."""
    deps = {}
    for pkg in ["numpy", "scipy", "matplotlib", "pandas"]:
        try:
            mod = __import__(pkg)
            deps[pkg] = getattr(mod, "__version__", "unknown")
        except ImportError:
            deps[pkg] = "not installed"
    return deps


def write_manifest(
    output_root: str,
    csv_files: Optional[Dict[str, str]] = None,
    plot_files: Optional[Dict[str, str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Write a manifest.json to output_root.

    Parameters
    ----------
    output_root : str
        Directory containing CSV and plot artifacts.
    csv_files : dict, optional
        Mapping of logical name -> CSV file path (relative or absolute).
    plot_files : dict, optional
        Mapping of logical name -> PNG file path.
    extra : dict, optional
        Additional metadata to include.

    Returns
    -------
    str
        Path to the written manifest.json.
    """
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    git_info = _get_git_info(repo_dir)

    manifest: Dict[str, Any] = {
        "protocol": "GMCP-R",
        "protocol_version": "1.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generated_timestamp": time.time(),
        "git": git_info,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "os": f"{platform.system()} {platform.release()}",
        "dependencies": _get_dependencies(),
        "command_line": " ".join(sys.argv),
        "seed": os.environ.get("GMCP_SEED", "demo-seed"),
        "lock_strategy": os.environ.get("GMCP_LOCK_STRATEGY", "per_session_lock"),
        "limitations": [
            "Prototype system using HMAC-SHA256 for authentication",
            "Seq+MAC and Ticket Only have no history-pointer attacks (N/A in detection denominator)",
            "Plain Hash Chain is negative control only",
            "All experiments are local TCP only",
        ],
        "csv_hashes": {},
        "plot_hashes": {},
    }

    if extra:
        manifest.update(extra)

    # Compute hashes for CSV files
    if csv_files:
        for name, path in csv_files.items():
            abs_path = path if os.path.isabs(path) else os.path.join(output_root, path)
            if os.path.isfile(abs_path):
                manifest["csv_hashes"][name] = {
                    "path": os.path.relpath(abs_path, output_root),
                    "sha256": sha256_file(abs_path),
                    "size_bytes": os.path.getsize(abs_path),
                }

    # Compute hashes for plot files
    if plot_files:
        for name, path in plot_files.items():
            abs_path = path if os.path.isabs(path) else os.path.join(output_root, path)
            if os.path.isfile(abs_path):
                manifest["plot_hashes"][name] = {
                    "path": os.path.relpath(abs_path, output_root),
                    "sha256": sha256_file(abs_path),
                    "size_bytes": os.path.getsize(abs_path),
                }

    manifest_path = os.path.join(output_root, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(f"[MANIFEST] Written to {manifest_path}")
    return manifest_path


def validate_revision(
    output_root: str,
    expected_repeats: int = 30,
    manifest_path: Optional[str] = None,
) -> List[str]:
    """
    Validate submission revision artifacts against expected contracts.

    Returns a list of violation strings. Empty list means VALID.
    """
    violations: List[str] = []

    # --- Load manifest ---
    mp = manifest_path or os.path.join(output_root, "manifest.json")
    if not os.path.isfile(mp):
        violations.append(f"manifest.json not found at {mp}")
        return violations

    with open(mp, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # --- Verify CSV hashes from manifest ---
    csv_hashes = manifest.get("csv_hashes", {})
    for name, info in csv_hashes.items():
        csv_path = os.path.join(output_root, info["path"])
        if not os.path.isfile(csv_path):
            violations.append(f"CSV '{name}' missing: {info['path']}")
            continue
        actual = sha256_file(csv_path)
        if actual != info["sha256"]:
            violations.append(
                f"CSV '{name}' hash mismatch: expected {info['sha256'][:16]}..., got {actual[:16]}..."
            )

    # --- Verify plot hashes from manifest ---
    plot_hashes = manifest.get("plot_hashes", {})
    for name, info in plot_hashes.items():
        plot_path = os.path.join(output_root, info["path"])
        if not os.path.isfile(plot_path):
            violations.append(f"Plot '{name}' missing: {info['path']}")
            continue
        if os.path.getsize(plot_path) == 0:
            violations.append(f"Plot '{name}' is empty: {info['path']}")
            continue
        actual = sha256_file(plot_path)
        if actual != info["sha256"]:
            violations.append(
                f"Plot '{name}' hash mismatch: expected {info['sha256'][:16]}..., got {actual[:16]}..."
            )

    # --- Validate specific CSV contracts ---
    violations.extend(_validate_baseline_csv(output_root))
    violations.extend(_validate_adaptive_attack_csv(output_root))
    violations.extend(_validate_recovery_window_csv(output_root, expected_repeats))
    violations.extend(_validate_checkpoint_cost_csv(output_root, expected_repeats))
    violations.extend(_validate_concurrent_csv(output_root, expected_repeats))

    return violations


def _read_csv(path: str) -> List[Dict[str, str]]:
    """Read CSV and return list of rows."""
    import csv
    if not os.path.isfile(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _validate_baseline_csv(output_root: str) -> List[str]:
    """Validate baseline comparison CSV."""
    violations = []
    path = os.path.join(output_root, "baseline_comparison.csv")
    if not os.path.isfile(path):
        # Also check the legacy location
        alt = os.path.join(output_root, "real_baseline_comparison_results.csv")
        if not os.path.isfile(alt):
            return violations  # optional; only validate if present
        path = alt

    rows = _read_csv(path)
    if not rows:
        violations.append("baseline CSV is empty")
        return violations

    required = {"protocol", "attack_type", "message_count", "payload_size", "repeat_id",
                "success_rate", "attack_injected", "attack_detected_by_server"}
    missing = required - set(rows[0].keys())
    if missing:
        violations.append(f"baseline CSV missing columns: {missing}")

    # Check N/A attack semantics
    na_protocols = {"seq_mac", "ticket_only"}
    na_attacks = {"prev_mem"}
    for row in rows:
        proto = row.get("protocol", "")
        attack = row.get("attack_type", "")
        if proto in na_protocols and attack in na_attacks:
            if str(row.get("attack_injected", "")).lower() == "true":
                violations.append(
                    f"N/A attack should not be injected for {proto}/{attack}"
                )

    return violations


def _validate_adaptive_attack_csv(output_root: str) -> List[str]:
    """Validate adaptive attack CSV."""
    violations = []
    path = os.path.join(output_root, "hash_chain_adaptive_attack.csv")
    if not os.path.isfile(path):
        return violations

    rows = _read_csv(path)
    if not rows:
        violations.append("adaptive attack CSV is empty")
        return violations

    required = {"protocol", "attack_applicable", "attack_accepted"}
    missing = required - set(rows[0].keys())
    if missing:
        violations.append(f"adaptive attack CSV missing columns: {missing}")

    # Duplicate keys check
    keys = [(r.get("protocol", ""), r.get("attack_type", "")) for r in rows]
    if len(keys) != len(set(keys)):
        violations.append("adaptive attack CSV has duplicate composite keys")

    # Authenticated chain should reject
    for row in rows:
        if row.get("protocol") == "authenticated_hash_chain":
            if str(row.get("attack_accepted", "")).lower() == "true":
                violations.append("authenticated_hash_chain should reject adaptive attack")
        if row.get("protocol") == "hash_chain":
            if str(row.get("attack_applicable", "")).lower() == "true":
                if str(row.get("attack_accepted", "")).lower() != "true":
                    violations.append("plain hash_chain should accept adaptive attack")

    return violations


def _validate_recovery_window_csv(output_root: str, expected_repeats: int) -> List[str]:
    """Validate recovery window experiment CSV."""
    violations = []
    path = os.path.join(output_root, "recovery_window_experiment.csv")
    if not os.path.isfile(path):
        return violations

    rows = _read_csv(path)
    if not rows:
        violations.append("recovery window CSV is empty")
        return violations

    required = {
        "scenario", "checkpoint_interval", "payload_size", "repeat_id",
        "ticket_seq", "client_seq", "server_seq", "floor_seq", "response_seq",
        "gap", "response_advance", "request_auth_ok", "response_auth_ok",
        "nonce_match", "nonce_consumed", "race_winner_count", "state_unchanged",
        "success", "reason",
    }
    missing = required - set(rows[0].keys())
    if missing:
        violations.append(f"recovery window CSV missing columns: {missing}")

    # Duplicate composite keys
    keys = [
        (r.get("scenario"), r.get("checkpoint_interval"), r.get("payload_size"), r.get("repeat_id"))
        for r in rows
    ]
    if len(keys) != len(set(keys)):
        violations.append("recovery window CSV has duplicate composite keys")

    # Row count
    non_race = [r for r in rows if r.get("scenario") != "nonce_race"]
    race = [r for r in rows if r.get("scenario") == "nonce_race"]

    if expected_repeats == 30:
        if len(rows) != 540:
            violations.append(f"recovery window expected 540 rows, got {len(rows)}")
        if len(non_race) != 480:
            violations.append(f"expected 480 non-race rows, got {len(non_race)}")
        if len(race) != 60:
            violations.append(f"expected 60 race rows, got {len(race)}")

    # Below-floor must leave state unchanged
    for row in rows:
        if row.get("scenario") == "below_floor":
            if str(row.get("state_unchanged", "")).lower() != "true":
                violations.append(
                    f"below_floor row did not leave state unchanged: {row}"
                )
            if str(row.get("success", "")).lower() == "true":
                violations.append(f"below_floor should be rejected: {row}")

    # Race must have exactly 1 winner
    for row in race:
        winners = int(row.get("race_winner_count") or 0)
        if winners != 1:
            violations.append(f"nonce_race winner count should be 1, got {winners}")

    return violations


def _validate_checkpoint_cost_csv(output_root: str, expected_repeats: int) -> List[str]:
    """Validate checkpoint cost comparison CSV."""
    violations = []
    path = os.path.join(output_root, "checkpoint_cost_comparison.csv")
    if not os.path.isfile(path):
        return violations

    rows = _read_csv(path)
    if not rows:
        violations.append("checkpoint cost CSV is empty")
        return violations

    required = {"protocol", "n", "k", "offset", "repeat_id", "replay_count",
                "recovery_material_bytes", "target_state_match"}
    missing = required - set(rows[0].keys())
    if missing:
        violations.append(f"checkpoint cost CSV missing columns: {missing}")

    # Duplicate composite keys
    keys = [
        (r.get("protocol"), r.get("n"), r.get("k"), r.get("offset"), r.get("repeat_id"))
        for r in rows
    ]
    if len(keys) != len(set(keys)):
        violations.append("checkpoint cost CSV has duplicate composite keys")

    # Matrix coverage: check all (n, k) combos exist
    combos = set((r.get("n"), r.get("k")) for r in rows)
    n_values = set(r.get("n") for r in rows)
    k_values = set(r.get("k") for r in rows)
    expected_combos = set()
    for n in n_values:
        for k in k_values:
            if int(k) < int(n):
                expected_combos.add((n, k))
    missing_combos = expected_combos - combos
    if missing_combos:
        violations.append(f"checkpoint cost CSV missing matrix combos: {missing_combos}")

    # All reconstruction must match
    mismatches = [
        r for r in rows if str(r.get("target_state_match", "")).lower() != "true"
    ]
    if mismatches:
        violations.append(
            f"{len(mismatches)} checkpoint cost rows have state mismatch"
        )

    # Expected row count for full run
    if expected_repeats == 30:
        # 3 n-values × valid k-combos × 3 offsets × 2 protocols × 30 repeats
        expected_rows = len(n_values) * len(expected_combos) * 3 * 2 * 30
        if expected_rows == 2160 and len(rows) != 2160:
            violations.append(
                f"checkpoint cost expected 2160 rows, got {len(rows)}"
            )

    return violations


def _validate_concurrent_csv(output_root: str, expected_repeats: int) -> List[str]:
    """Validate concurrent experiment CSV."""
    violations = []
    path = os.path.join(output_root, "concurrent_results.csv")
    if not os.path.isfile(path):
        # Also check legacy location
        alt = os.path.join("results/concurrent", "concurrent_results.csv")
        if not os.path.isfile(alt):
            return violations
        path = alt

    rows = _read_csv(path)
    if not rows:
        return violations

    required = {"concurrency", "repeat_id"}
    missing = required - set(rows[0].keys())
    if missing:
        violations.append(f"concurrent CSV missing columns: {missing}")

    return violations
