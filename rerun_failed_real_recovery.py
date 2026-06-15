# -*- coding: utf-8 -*-
# rerun_failed_real_recovery.py

import argparse
import csv
from typing import Dict, List

from run_real_recovery_experiment import OUTPUT_CSV, run_one_recovery_experiment


def as_bool(value) -> bool:
    return str(value).strip().lower() == "true"


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def is_failed_recovery_row(row: Dict[str, str]) -> bool:
    reason = str(row.get("detection_reason", "")).lower()
    return (
        not as_bool(row.get("full_recovery_success", ""))
        or not as_bool(row.get("recovery_success", ""))
        or as_int(row.get("timeout_count", "0")) > 0
        or "server closed connection" in reason
        or "tcp error" in reason
    )


def row_case(row: Dict[str, str]) -> Dict[str, int]:
    return {
        "attack_type": row["attack_type"],
        "message_count": as_int(row["message_count"]),
        "payload_size": as_int(row["payload_size"]),
        "repeat_id": as_int(row["repeat_id"]),
    }


def compatible_row(new_row: Dict[str, object], fieldnames: List[str]) -> Dict[str, object]:
    return {key: new_row.get(key, "") for key in fieldnames}


def rerun_failed_rows(input_csv: str, attempts: int, dry_run: bool) -> int:
    with open(input_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[RERUN_RECOVERY] no rows found in", input_csv)
        return 0

    fieldnames = list(rows[0].keys())
    failed_indexes = [idx for idx, row in enumerate(rows) if is_failed_recovery_row(row)]

    print("[RERUN_RECOVERY] input:", input_csv)
    print("[RERUN_RECOVERY] failed rows:", len(failed_indexes))

    if dry_run:
        for idx in failed_indexes:
            print("[RERUN_RECOVERY][DRY_RUN]", idx, row_case(rows[idx]), rows[idx].get("detection_reason"))
        return len(failed_indexes)

    replaced = 0

    for idx in failed_indexes:
        case = row_case(rows[idx])
        print("[RERUN_RECOVERY] rerun index=", idx, "case=", case)

        best_row = None
        for attempt in range(1, attempts + 1):
            new_row = run_one_recovery_experiment(**case)
            print(
                "[RERUN_RECOVERY]",
                "attempt=", attempt,
                "attack=", case["attack_type"],
                "messages=", case["message_count"],
                "payload=", case["payload_size"],
                "repeat=", case["repeat_id"],
                "accepted=", new_row.get("accepted_count"),
                "timeout=", new_row.get("timeout_count"),
                "full_success=", new_row.get("full_recovery_success"),
                "reason=", new_row.get("detection_reason"),
            )
            best_row = new_row
            if not is_failed_recovery_row({key: str(value) for key, value in new_row.items()}):
                break

        if best_row is not None:
            rows[idx] = compatible_row(best_row, fieldnames)
            replaced += 1

    with open(input_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print("[RERUN_RECOVERY] replaced rows:", replaced)
    print("[RERUN_RECOVERY] updated:", input_csv)
    return replaced


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rerun failed rows in results/real_recovery/real_recovery_results.csv."
    )
    parser.add_argument("--input-csv", default=OUTPUT_CSV)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    rerun_failed_rows(args.input_csv, attempts=args.attempts, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
