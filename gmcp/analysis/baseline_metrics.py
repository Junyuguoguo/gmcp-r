# -*- coding: utf-8 -*-
"""
gmcp/analysis/baseline_metrics.py

Shared baseline statistics functions used by:
  - generate_experiment_summary.py
  - validate_release_artifacts.py
  - validate_weak_network_artifact.py
  - tests/test_experiment_statistics.py

All numeric claims are computed from CSV data, never hardcoded.
"""

from typing import Dict, List, Optional, Tuple

import pandas as pd
import numpy as np


# ── Protocol Display Names ────────────────────────────────────────────────────
# Canonical mapping from CSV protocol keys → human-readable paper names.
# Keys are sorted alphabetically; use PROTOCOL_DISPLAY_NAMES_SORTED for
# deterministic iteration order.

PROTOCOL_DISPLAY_NAMES: Dict[str, str] = {
    "authenticated_hash_chain": "Authenticated Hash Chain",
    "gmcp_r": "GMCP-R",
    "hash_chain": "Hash Chain",
    "seq_mac": "Seq+MAC",
    "ticket_only": "Ticket Only",
}

# Deterministic iteration order (alphabetical by key)
PROTOCOL_DISPLAY_NAMES_SORTED: List[Tuple[str, str]] = sorted(
    PROTOCOL_DISPLAY_NAMES.items()
)


def display_name(protocol_key: str) -> str:
    """Return the paper-facing display name for a protocol key."""
    return PROTOCOL_DISPLAY_NAMES.get(protocol_key, protocol_key.replace("_", " ").title())


# ── Baseline Statistics ───────────────────────────────────────────────────────

def filter_baseline(df: pd.DataFrame) -> pd.DataFrame:
    """
    Filter baseline CSV to rows used for statistics.
    
    Denominator = rows where attack_applicable == True AND sent_count > 0.
    This covers both normal (attack_injected=False) and attack (attack_injected=True) rows.
    """
    return df[(df["attack_applicable"] == True) & (df["sent_count"] > 0)].copy()


def baseline_protocol_stats(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    """
    Compute per-protocol baseline statistics from 01_real_baseline.csv.
    
    Returns dict keyed by protocol name with:
      - throughput: mean throughput_msg_per_sec for normal rows
      - rtt_mean: mean rtt_mean_ms for normal rows
      - detection_rate: % of attack rows where attack_detected_by_server == True
      - false_accept_rate: % of attack rows where attack was NOT detected
      - false_reject_rate: % of normal rows where rejected_count > 0
    """
    filtered = filter_baseline(df)
    protocols = sorted(filtered["protocol"].unique())
    
    stats = {}
    for proto in protocols:
        normal = filtered[(filtered["protocol"] == proto) & (filtered["attack_injected"] == False)]
        attack = filtered[(filtered["protocol"] == proto) & (filtered["attack_injected"] == True)]
        
        throughput = normal["throughput_msg_per_sec"].mean() if len(normal) > 0 else 0.0
        rtt_mean = normal["rtt_mean_ms"].mean() if len(normal) > 0 else 0.0
        
        if len(normal) > 0:
            false_reject_rate = (normal["rejected_count"] > 0).sum() / len(normal) * 100
        else:
            false_reject_rate = 0.0
        
        if len(attack) > 0:
            detection_rate = attack["attack_detected_by_server"].sum() / len(attack) * 100
            false_accept_rate = (1 - attack["attack_detected_by_server"].sum() / len(attack)) * 100
        else:
            detection_rate = 0.0
            false_accept_rate = 0.0
        
        stats[proto] = {
            "throughput": throughput,
            "rtt_mean": rtt_mean,
            "detection_rate": detection_rate,
            "false_accept_rate": false_accept_rate,
            "false_reject_rate": false_reject_rate,
            "normal_count": len(normal),
            "attack_count": len(attack),
        }
    
    return stats


# ── Weak-Network Statistics ───────────────────────────────────────────────────

def weak_network_group_stats(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute grouped weak-network statistics from 05_weak_network.csv.
    
    Groups by (protocol, loss_rate, delay_ms) and returns a DataFrame with:
      - success_rate_mean, throughput_mean, rtt_mean, repeat_count
    """
    grouped = df.groupby(["protocol", "loss_rate", "delay_ms"], sort=True).agg(
        success_rate_mean=("success_rate", "mean"),
        throughput_mean=("throughput_msg_per_sec", "mean"),
        rtt_mean=("rtt_mean_ms", "mean"),
        repeat_count=("repeat_id", "count"),
    ).reset_index()
    return grouped


def weak_network_protocol_summary(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute per-protocol weak-network summary (aggregated over all loss/delay).
    """
    grouped = df.groupby(["protocol"], sort=True).agg(
        success_rate_mean=("success_rate", "mean"),
        throughput_mean=("throughput_msg_per_sec", "mean"),
        rtt_mean=("rtt_mean_ms", "mean"),
        row_count=("protocol", "count"),
    ).reset_index()
    return grouped


# ── Formatting Helpers ────────────────────────────────────────────────────────

def fmt_pct(v: float, digits: int = 1) -> str:
    return f"{v:.{digits}f}%"


def fmt_num(v: float, digits: int = 0) -> str:
    """Format number with comma separator."""
    if digits == 0:
        return f"{v:,.0f}"
    return f"{v:,.{digits}f}"


def fmt_ms(v: float, digits: int = 3) -> str:
    return f"{v:.{digits}f} ms"


def fmt_us(v: float, digits: int = 1) -> str:
    return f"{v:.{digits}f} µs"


# ── Matrix Validation ─────────────────────────────────────────────────────────

EXPECTED_WEAK_NETWORK_MATRIX = {
    "protocols": ["gmcp_r", "hash_chain", "seq_mac"],
    "loss_rates": [0, 1, 2, 5, 10],
    "delay_ms": [0, 20, 50, 100, 200],
    "repeats": [1, 2],
}
EXPECTED_WEAK_NETWORK_ROW_COUNT = 3 * 5 * 5 * 2  # = 150
