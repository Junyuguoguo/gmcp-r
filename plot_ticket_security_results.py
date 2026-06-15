# -*- coding: utf-8 -*-
# plot_ticket_security_results.py

import glob
import os

import matplotlib.pyplot as plt
import pandas as pd


INPUT_CSV = "results/ticket_security/ticket_security_results.csv"
OUTPUT_DIR = "results/ticket_security/figures"
SUMMARY_CSV = "results/ticket_security/summary_ticket_security.csv"


def ensure_output_dir() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def clean_old_figures() -> None:
    for path in glob.glob(os.path.join(OUTPUT_DIR, "*.png")):
        os.remove(path)


def bool_series(series):
    return series.astype(str).str.lower() == "true"


def save_bar(series, xlabel, ylabel, title, output_path, rotation=45) -> None:
    plt.figure(figsize=(8, 5))
    series.plot(kind="bar")
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=rotation)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def main() -> None:
    ensure_output_dir()
    clean_old_figures()

    df = pd.read_csv(INPUT_CSV)
    for col in ["ticket_valid", "ticket_verified", "attack_detected", "recovery_allowed"]:
        df[col + "_bool"] = bool_series(df[col])

    detection = df.groupby("attack_type")["attack_detected_bool"].mean()
    save_bar(
        detection,
        "Ticket type",
        "Attack detection rate",
        "MemoryTicket Attack Detection Rate",
        os.path.join(OUTPUT_DIR, "ticket_fig1_ticket_attack_detection_rate.png"),
    )

    allowed = df.groupby("attack_type")["recovery_allowed_bool"].mean()
    save_bar(
        allowed,
        "Ticket type",
        "Recovery allowed rate",
        "Recovery Allowed by MemoryTicket Type",
        os.path.join(OUTPUT_DIR, "ticket_fig2_recovery_allowed_by_ticket_type.png"),
    )

    summary = df.groupby("attack_type").agg(
        ticket_verified_rate=("ticket_verified_bool", "mean"),
        attack_detection_rate=("attack_detected_bool", "mean"),
        recovery_allowed_rate=("recovery_allowed_bool", "mean"),
    )
    summary.to_csv(SUMMARY_CSV, encoding="utf-8")

    print("[TICKET_SECURITY_PLOT] figures saved to", OUTPUT_DIR)
    print("[TICKET_SECURITY_PLOT] summary saved to", SUMMARY_CSV)


if __name__ == "__main__":
    main()
