# -*- coding: utf-8 -*-
# validate_experiment_results.py

import csv
import os
from typing import Callable, Dict, Iterable, List, Optional


CHECK_FILES = [
    ("baseline CSV", "results/baseline/baseline_comparison_results.csv"),
    (
        "baseline figure",
        "results/baseline/figures/baseline_fig1_recovery_latency_by_protocol.png",
    ),
    ("real_network CSV", "results/real_network/real_network_results.csv"),
    (
        "real_network memory figure",
        "results/real_network/memory_figures/memory_fig6_window_memory_match.png",
    ),
    ("real_recovery CSV", "results/real_recovery/real_recovery_results.csv"),
    (
        "real_recovery figure",
        "results/real_recovery/figures/recovery_fig1_success_rate_by_attack.png",
    ),
    ("weak_network CSV", "results/weak_network/weak_network_results.csv"),
    ("ticket_security CSV", "results/ticket_security/ticket_security_results.csv"),
]


def read_rows(path: str) -> Optional[List[Dict[str, str]]]:
    if not os.path.exists(path):
        return None
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def as_bool(value: str) -> bool:
    return str(value).lower() == "true"


def rate(rows: Iterable[Dict[str, str]], predicate: Callable[[Dict[str, str]], bool]) -> Optional[float]:
    rows = list(rows)
    if not rows:
        return None
    return sum(1 for row in rows if predicate(row)) / len(rows)


def print_file_checks() -> None:
    print("[VALIDATE] File checks")
    for name, path in CHECK_FILES:
        if os.path.exists(path):
            print(f"PASS: {name} -> {path}")
        else:
            print(f"MISSING: {name} -> {path}")


def print_metric(name: str, value: Optional[float], expected: float = 1.0) -> None:
    if value is None:
        print(f"MISSING: {name}")
    elif abs(value - expected) < 1e-9:
        print(f"PASS: {name} = {value:.4f}")
    else:
        print(f"FAIL: {name} = {value:.4f}, expected {expected:.4f}")


def main() -> None:
    print_file_checks()
    print("[VALIDATE] Metric checks")

    real_rows = read_rows("results/real_network/real_network_results.csv")
    if real_rows is None:
        print_metric("real memory_match_rate", None)
        print_metric("real prev_mem detection rate", None)
    else:
        normal_rows = [row for row in real_rows if row.get("attack_type") == "none"]
        prev_mem_rows = [row for row in real_rows if row.get("attack_type") == "prev_mem"]
        print_metric(
            "real memory_match_rate",
            rate(normal_rows, lambda row: as_bool(row.get("memory_match", ""))),
        )
        print_metric(
            "real prev_mem detection rate",
            rate(prev_mem_rows, lambda row: as_bool(row.get("attack_detected", ""))),
        )

    recovery_rows = read_rows("results/real_recovery/real_recovery_results.csv")
    if recovery_rows is None:
        print_metric("recovery full_recovery_success", None)
        print_metric("recovery memory_match_after_recovery", None)
    else:
        print_metric(
            "recovery full_recovery_success",
            rate(recovery_rows, lambda row: as_bool(row.get("full_recovery_success", ""))),
        )
        print_metric(
            "recovery memory_match_after_recovery",
            rate(recovery_rows, lambda row: as_bool(row.get("memory_match_after_recovery", ""))),
        )

    ticket_rows = read_rows("results/ticket_security/ticket_security_results.csv")
    if ticket_rows is None:
        print_metric("ticket invalid attacks detection rate", None)
    else:
        invalid_rows = [row for row in ticket_rows if row.get("attack_type") != "valid_ticket"]
        print_metric(
            "ticket invalid attacks detection rate",
            rate(invalid_rows, lambda row: as_bool(row.get("attack_detected", ""))),
        )


if __name__ == "__main__":
    main()
