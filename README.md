# GMCP-R: Memory-Continuity-Aware Secure Recovery

GMCP-R is a Python TCP prototype for studying verifiable historical-state
recovery in intermittent communication. It combines a memory hash chain,
MemoryTicket recovery, and checkpoints so a session can recover while still
checking whether the recovered state belongs to the same communication history.

## Current Evidence

The current paper-facing data is under `paper_data/` and mirrors the latest
CSV results used by the manuscript.

| Dataset | Rows | Repeats | Scope |
|---|---:|---:|---|
| `01_real_baseline.csv` | 3,600 | 30/config | GMCP-R vs Hash Chain, Seq+MAC, Ticket Only |
| `02_ticket_attacks.csv` | 300 | 30/config | Invalid MemoryTicket rejection |
| `03_performance.csv` | 120 | 3/config | Local computation benchmark |
| `04_concurrency.csv` | 15 | 3/config | 1-20 concurrent clients |
| `05_weak_network.csv` | 150 | 2/config | Preliminary code-level weak-network simulation |
| `06_memory_ticket_recovery.csv` | 900 | 30/config | Attack/disconnect recovery |
| `07_checkpoint_recovery.csv` | 120 | 10/config | Checkpoint reconstruction audit |

## Key Results

### Baseline Comparison

Source: `results/real_baseline_comparison/summary_real_baseline_comparison_v2.csv`

| Protocol | Normal Throughput | Normal RTT | Attack Detection | False Accept |
|---|---:|---:|---:|---:|
| GMCP-R | 10,614 msg/s | 0.093 ms | 100% | 0% |
| Hash Chain | 13,008 msg/s | 0.084 ms | 100% | 0% |
| Seq+MAC | 13,148 msg/s | 0.080 ms | 75% | 25% |
| Ticket Only | 13,516 msg/s | 0.083 ms | 50% | 50% |

GMCP-R and Hash Chain have the same tested attack-detection rate. GMCP-R's
incremental contribution is verifiable recovery through MemoryTicket and
Checkpoint support.

### Recovery and Ticket Security

- Real attack/disconnect recovery: 900/900 successful recoveries, 100% memory
  match, and 100% ticket verification in the current local TCP loopback data.
- Invalid MemoryTicket tests: 300/300 invalid tickets rejected across expired,
  replayed, tampered, rollback, and wrong-session cases.
- Checkpoint reconstruction: 120/120 rows reconstruct the target memory state,
  with replay count matching `target_seq - checkpoint_seq`.

### Performance and Concurrency

- Local computation throughput for GMCP-R averages about 65,931 msg/s.
- GMCP-R is not the fastest protocol; the overhead buys history-continuity and
  recovery-state checks.
- Concurrent-client throughput peaks at 17,927 msg/s with 5 clients, while all
  tested levels from 1 to 20 clients keep 100% success.

### Weak-Network Simulation

The weak-network data is preliminary code-level simulation only. It simulates
loss and delay in application code; it is not a Linux `tc/netem`, ns-3, or
real weak-network experiment. Treat it as supplemental evidence for recovery
behavior, not as a core deployment claim.

## Verification

Use the project virtual environment; the system Python on this machine may not
have the required packages.

```bash
./.venv/bin/python validate_experiment_results.py
./.venv/bin/python -m unittest discover -v -s tests -p 'test*.py'
```

## Manuscript Sources

- Main Chinese manuscript: `paper/main_zh.md`
- DOCX generator: `paper/build_mdpi_chinese_docx.py`
- Main DOCX output: `paper/GMCP-R_MDPI_Electronics_中文初稿.docx`
- Render QA output: `paper/rendered_docx_qa/`

The old `paper/main.tex` is retained as a lightweight LaTeX reference only.
Do not use stale numeric claims from older drafts when writing the paper.
