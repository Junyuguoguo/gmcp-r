# GMCP-R Experiment Summary

Generated for the current `paper_data/` package. Numeric claims below are
derived from the current CSV files and should replace older draft prose.

## Data Package

| File | Experiment | Rows | Repeat Count | Environment |
|---|---|---:|---:|---|
| `paper_data/01_real_baseline.csv` | Baseline comparison | 7,200 | 30/config | Python TCP prototype |
| `paper_data/02_ticket_attacks.csv` | Invalid MemoryTicket attacks | 300 | 30/config | Local TCP loopback |
| `paper_data/03_performance.csv` | Local computation benchmark | 1,200 | 30/config | Local computation |
| `paper_data/04_concurrency.csv` | Concurrent clients | 150 | 30/config | Local TCP loopback |
| `paper_data/05_weak_network.csv` | Weak-network simulation | 150 | 2/config | Code-level simulation |
| `paper_data/06_memory_ticket_recovery.csv` | Attack/disconnect recovery | 900 | 30/config | Local TCP loopback |
| `paper_data/07_checkpoint_recovery.csv` | Checkpoint recovery | 120 | 10/config | Local TCP loopback |
| `paper_data/08_recovery_window.csv` | Recovery window + ACK loss + nonce race | 760 | 30/config | Local TCP loopback |
| `paper_data/09_checkpoint_cost.csv` | O(k) vs O(n) checkpoint recovery cost | 2,160 | 30/config | Local computation |

Total paper-facing rows: 12,940.

## Baseline Comparison

Source: `results/real_baseline_comparison/summary_real_baseline_comparison_v2.csv`

| Protocol | Normal Throughput | Normal RTT | Attack Detection | False Accept | False Reject |
|---|---:|---:|---:|---:|---:|
| GMCP-R | 10,341 msg/s | 0.091 ms | 100.0% | 0.0% | 0% |
| Hash Chain | 12,642 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |
| Seq+MAC | 12,760 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |
| Authenticated Hash Chain | 9,655 msg/s | 0.098 ms | 100.0% | 0.0% | 0% |
| Ticket Only | 13,177 msg/s | 0.083 ms | 83.3% | 16.7% | 0% |

Interpretation: GMCP-R should not be described as detecting more tested attacks
than Hash Chain. Both reach 100% in this matrix. The distinction is recovery:
GMCP-R additionally supports MemoryTicket and Checkpoint-based state recovery.

## MemoryTicket and Recovery

Invalid-ticket experiments reject all 300 invalid tickets. The rejected cases
cover expired tickets, replayed tickets, tampered tickets, rollback tickets, and
wrong-session tickets.

The real recovery dataset contains 900 rows:

- 5 scenarios: `drop`, `modify`, `replay`, `prev_mem`, `disconnect`
- 3 message counts: 200, 500, 1000
- 2 payload sizes: 128 and 512 bytes
- 30 repeats per configuration

All current recovery rows have successful recovery, memory match after recovery,
server ticket verification, and response-state match.

## Checkpoint Recovery

Checkpoint recovery contains 120 rows across 3 scenarios, 2 message counts, 2
checkpoint intervals, and 10 repeats. The current data records `checkpoint_seq`,
`target_seq`, `replay_count`, `target_mem`, and `reconstructed_mem`, making the
O(k) recovery claim auditable within the prototype.

## Performance

Source: `paper_data/03_performance.csv`

| Protocol | Mean Throughput | Mean E2E Latency |
|---|---:|---:|
| GMCP-R | 10,341 msg/s | 0.091 ms | 100.0% | 0.0% | 0% |
| Hash Chain | 12,642 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |
| Seq+MAC | 12,760 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |
| Ticket Only | 13,177 msg/s | 0.083 ms | 83.3% | 16.7% | 0% |

Interpretation: GMCP-R is slower than the lightweight baselines, but still
offers about 6.6e4 msg/s in the local computation benchmark. The paper should
frame this as acceptable overhead for extra recovery/security capability, not
as best-in-class performance.

## Concurrency

Source: `paper_data/04_concurrency.csv`

| Clients | Mean Throughput | Mean RTT | Success |
|---:|---:|---:|---:|
| 1 | 7,037 msg/s | 0.125 ms | 100% |
| 2 | 14,204 msg/s | 0.124 ms | 100% |
| 5 | 17,927 msg/s | 0.255 ms | 100% |
| 10 | 16,452 msg/s | 0.571 ms | 100% |
| 20 | 15,645 msg/s | 1.216 ms | 100% |

## Weak-Network Simulation

Source: `results/weak_network_simulation/summary_weak_network_simulation.csv`

| Protocol | Mean Success | Success Std | Mean Throughput | Mean RTT | n |
|---|---:|---:|---:|---:|---:|
| GMCP-R | 10,341 msg/s | 0.091 ms | 100.0% | 0.0% | 0% |
| Hash Chain | 12,642 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |
| Seq+MAC | 12,760 msg/s | 0.082 ms | 100.0% | 0.0% | 0% |

This is code-level simulation: 3 protocols x 5 loss rates x 5 delay settings x
2 repeats = 150 rows. Do not present this as a real weak-network result.

## Remaining Work Before Submission

- Replace manuscript placeholders for author contributions, affiliations, and
  acknowledgments with final author-approved text.
- Run a real `tc/netem` or ns-3 weak-network experiment before making strong
  deployment claims.
- Increase baseline/performance/concurrency repeats if the target venue expects
  stronger statistical inference.
- Keep the manuscript and DOCX generated from current CSVs, not older draft
  values.
