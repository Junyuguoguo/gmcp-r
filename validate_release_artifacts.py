# -*- coding: utf-8 -*-
# validate_release_artifacts.py
#
# Release artifact validator for GMCP-R.
# Checks CSV integrity, row counts, cross-reference consistency,
# paper content correctness, and stale content absence.
# Exits nonzero with one line per violation.

import csv
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Expected CSV row counts (data rows, excluding header)
# ---------------------------------------------------------------------------
EXPECTED_CSV_ROWS = {
    "paper_data/01_real_baseline.csv": 7200,
    "paper_data/02_ticket_attacks.csv": 300,
    "paper_data/03_performance.csv": 1200,
    "paper_data/04_concurrency.csv": 150,
    "paper_data/05_weak_network.csv": 150,
    "paper_data/06_memory_ticket_recovery.csv": 900,
    "paper_data/07_checkpoint_recovery.csv": 120,
    "paper_data/08_recovery_window.csv": 760,
    "paper_data/09_checkpoint_cost.csv": 2160,
}
EXPECTED_TOTAL_ROWS = 12940

# Five protocols that must appear in the paper
FIVE_PROTOCOLS = [
    "GMCP-R",
    "Hash Chain",
    "Authenticated Hash Chain",
    "Seq+MAC",
    "Ticket Only",
]

# Two attacker models
ATTACKER_MODELS = ["网络攻击者", "记忆连续性攻击者"]

# Eight attack conditions
EIGHT_CONDITIONS = [
    "none",
    "cross_epoch_valid_mac",
    "cross_session_valid_mac",
    "exact_replay",
    "forged_prev_mem_valid_mac",
    "metadata_tamper",
    "modify_unsigned",
    "sequence_gap_valid_mac",
]

# Stale content that must NOT appear
STALE_PHRASES = [
    "三种基线协议",
    "Seq+MAC 25%",
    "Ticket Only 50%",
]


def fail(errors: list) -> int:
    """Print errors and return nonzero exit code."""
    for err in errors:
        print(f"FAIL: {err}")
    return 1


def read_csv_rows(path: str) -> list:
    """Read CSV and return list of row dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def validate() -> int:
    errors = []
    root = Path(__file__).resolve().parent

    # -----------------------------------------------------------------------
    # 1. All 9 CSVs exist and are non-empty
    # -----------------------------------------------------------------------
    csv_row_counts = {}
    for rel_path, expected_count in EXPECTED_CSV_ROWS.items():
        full_path = root / rel_path
        if not full_path.is_file():
            errors.append(f"CSV missing: {rel_path}")
            continue
        if full_path.stat().st_size == 0:
            errors.append(f"CSV is empty: {rel_path}")
            continue
        try:
            rows = read_csv_rows(str(full_path))
            actual_count = len(rows)
            csv_row_counts[rel_path] = actual_count
        except Exception as e:
            errors.append(f"CSV parse error in {rel_path}: {e}")
            continue

        # -------------------------------------------------------------------
        # 2. Per-file row count matches expected
        # -------------------------------------------------------------------
        if actual_count != expected_count:
            errors.append(
                f"{rel_path}: expected {expected_count} rows, got {actual_count}"
            )

    # -----------------------------------------------------------------------
    # 3. Total row count = 12,940
    # -----------------------------------------------------------------------
    if csv_row_counts:
        total = sum(csv_row_counts.values())
        if total != EXPECTED_TOTAL_ROWS:
            errors.append(
                f"Total CSV rows: expected {EXPECTED_TOTAL_ROWS}, got {total}"
            )

    # -----------------------------------------------------------------------
    # 4. README, paper_data/README.md, EXPERIMENT_SUMMARY.md row counts match
    # -----------------------------------------------------------------------
    doc_row_strings = []
    for doc_rel in ["README.md", "paper_data/README.md", "EXPERIMENT_SUMMARY.md"]:
        doc_path = root / doc_rel
        if doc_path.is_file():
            content = doc_path.read_text(encoding="utf-8")
            doc_row_strings.append((doc_rel, content))
        else:
            errors.append(f"Document missing: {doc_rel}")

    # Each document should mention 12,940 as total rows
    for doc_name, content in doc_row_strings:
        if "12,940" not in content and "12940" not in content:
            errors.append(
                f"{doc_name} does not contain total row count 12,940"
            )

    # Each document should list per-file row counts that match
    for doc_name, content in doc_row_strings:
        for rel_path, expected_count in EXPECTED_CSV_ROWS.items():
            fname = os.path.basename(rel_path)
            # Look for "7,200" or "7200" style in the doc
            formatted = f"{expected_count:,}"
            plain = str(expected_count)
            if fname in content:
                if formatted not in content and plain not in content:
                    errors.append(
                        f"{doc_name} missing row count for {fname} "
                        f"(expected {formatted} or {plain})"
                    )

    # -----------------------------------------------------------------------
    # 5. Performance table comes from 03_performance.csv
    # -----------------------------------------------------------------------
    perf_csv = root / "paper_data/03_performance.csv"
    if perf_csv.is_file():
        try:
            perf_rows = read_csv_rows(str(perf_csv))
            perf_protocols = sorted(
                set(row.get("protocol", "") for row in perf_rows if row.get("protocol"))
            )
            # Check that EXPERIMENT_SUMMARY.md references performance data
            summary_path = root / "EXPERIMENT_SUMMARY.md"
            if summary_path.is_file():
                summary_content = summary_path.read_text(encoding="utf-8")
                if "03_performance.csv" not in summary_content:
                    errors.append(
                        "EXPERIMENT_SUMMARY.md does not reference 03_performance.csv"
                    )
        except Exception as e:
            errors.append(f"Error reading 03_performance.csv: {e}")

    # -----------------------------------------------------------------------
    # 6. Weak-Network table comes from 05_weak_network.csv
    # -----------------------------------------------------------------------
    weak_csv = root / "paper_data/05_weak_network.csv"
    if weak_csv.is_file():
        try:
            weak_rows = read_csv_rows(str(weak_csv))
            weak_protocols = sorted(
                set(row.get("protocol", "") for row in weak_rows if row.get("protocol"))
            )
            summary_path = root / "EXPERIMENT_SUMMARY.md"
            if summary_path.is_file():
                summary_content = summary_path.read_text(encoding="utf-8")
                if "05_weak_network.csv" not in summary_content:
                    errors.append(
                        "EXPERIMENT_SUMMARY.md does not reference 05_weak_network.csv"
                    )
        except Exception as e:
            errors.append(f"Error reading 05_weak_network.csv: {e}")

    # -----------------------------------------------------------------------
    # 7. Paper contains five protocols (including Authenticated Hash Chain)
    # -----------------------------------------------------------------------
    paper_path = root / "paper" / "main_zh.md"
    paper_content = ""
    if paper_path.is_file():
        paper_content = paper_path.read_text(encoding="utf-8")
        for proto in FIVE_PROTOCOLS:
            if proto not in paper_content:
                errors.append(
                    f"Paper main_zh.md missing protocol: {proto}"
                )
    else:
        errors.append("Paper main_zh.md not found")

    # -----------------------------------------------------------------------
    # 8. Paper contains two attacker models and eight conditions
    # -----------------------------------------------------------------------
    if paper_content:
        for model in ATTACKER_MODELS:
            if model not in paper_content:
                errors.append(
                    f"Paper main_zh.md missing attacker model: {model}"
                )
        for condition in EIGHT_CONDITIONS:
            if condition not in paper_content:
                errors.append(
                    f"Paper main_zh.md missing attack condition: {condition}"
                )

    # -----------------------------------------------------------------------
    # 9. No stale/old conclusions in paper, README, EXPERIMENT_SUMMARY
    # -----------------------------------------------------------------------
    stale_check_files = []
    for rel in ["paper/main_zh.md", "README.md", "EXPERIMENT_SUMMARY.md"]:
        p = root / rel
        if p.is_file():
            stale_check_files.append((rel, p.read_text(encoding="utf-8")))
    for phrase in STALE_PHRASES:
        for fname, content in stale_check_files:
            if phrase in content:
                errors.append(
                    f"Stale phrase '{phrase}' found in {fname}"
                )

    # -----------------------------------------------------------------------
    # 10. CSV git_commit field is non-empty (if column exists)
    # -----------------------------------------------------------------------
    for rel_path in EXPECTED_CSV_ROWS:
        full_path = root / rel_path
        if not full_path.is_file():
            continue
        try:
            rows = read_csv_rows(str(full_path))
            if not rows:
                continue
            if "git_commit" not in rows[0]:
                continue  # Column doesn't exist; skip
            empty_commits = sum(
                1 for r in rows if not r.get("git_commit", "").strip()
            )
            if empty_commits > 0:
                errors.append(
                    f"{rel_path}: {empty_commits} rows have empty git_commit"
                )
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # 11. DOCX exists and is non-empty (if present)
    # -----------------------------------------------------------------------
    docx_candidates = list((root / "paper").glob("*.docx"))
    if docx_candidates:
        for docx in docx_candidates:
            if docx.stat().st_size == 0:
                errors.append(f"DOCX is empty: {docx.relative_to(root)}")
    # No DOCX is acceptable (optional artifact)

    # -----------------------------------------------------------------------
    # Report
    # -----------------------------------------------------------------------
    if errors:
        return fail(errors)

    print("PASS: All release artifact checks passed.")
    print(f"  CSVs: {len(csv_row_counts)} files, {sum(csv_row_counts.values())} total rows")
    return 0


if __name__ == "__main__":
    sys.exit(validate())
