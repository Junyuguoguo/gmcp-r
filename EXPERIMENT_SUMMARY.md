# GMCP-R Experiment Summary
All numeric values below are computed automatically from the current
`paper_data/*.csv` files by `generate_experiment_summary.py`.
**Experiment environment**: Python 3.11, localhost TCP loopback
(127.0.0.1:9000 / 127.0.0.1:9001).

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

Total paper-facing rows: **12,940**.

## Baseline Comparison
Source: `paper_data/01_real_baseline.csv`
| Protocol | Normal Throughput | Normal RTT | Attack Detection | False Accept | False Reject |
|---|---:|---:|---:|---:|---:|
| Authenticated Hash Chain | 9,655 msg/s | 0.098 ms | 100.0% | 0.0% | 0.0% |
| GMCP-R | 10,341 msg/s | 0.091 ms | 100.0% | 0.0% | 0.0% |
| Hash Chain | 12,642 msg/s | 0.082 ms | 100.0% | 0.0% | 0.0% |
| Seq+MAC | 12,760 msg/s | 0.082 ms | 100.0% | 0.0% | 0.0% |
| Ticket Only | 13,177 msg/s | 0.083 ms | 83.3% | 16.7% | 0.0% |

Interpretation: Protocols with detection below 100%: Ticket Only (83.3%). GMCP-R additionally supports MemoryTicket and Checkpoint-based state recovery.

## Ticket Attack Rejection
Source: `paper_data/02_ticket_attacks.csv`
| Attack Type | Rows | Detected | Detection Rate | Rejection Reason |
|---|---:|---:|---:|---|
| `expired_ticket` | 60 | 60 | 100.0% | memory_ticket invalid: ticket expired |
| `replayed_ticket` | 60 | 60 | 100.0% | memory_ticket invalid: ticket replay detected |
| `rollback_ticket` | 60 | 60 | 100.0% | memory_ticket invalid: checkpoint_seq exceeds last_seq |
| `tampered_ticket` | 60 | 60 | 100.0% | memory_ticket invalid: invalid ticket auth tag |
| `wrong_session_ticket` | 60 | 60 | 100.0% | memory_ticket invalid: session_id mismatch |

All 300 invalid tickets were detected and rejected (100.0% detection rate).

## Performance
Source: `paper_data/03_performance.csv`
| Protocol | Throughput | Build P50 | Verify P50 | E2E P50 | E2E P99 |
|---|---:|---:|---:|---:|---:|
| GMCP-R | 63,998 msg/s | 7.0 µs | 7.9 µs | 14.9 µs | 25.1 µs |
| Hash Chain | 259,438 msg/s | 1.6 µs | 1.8 µs | 3.3 µs | 5.0 µs |
| Seq+MAC | 211,339 msg/s | 2.0 µs | 2.1 µs | 4.2 µs | 5.7 µs |
| Ticket Only | 366,046 msg/s | 0.3 µs | 1.9 µs | 2.2 µs | 2.9 µs |

GMCP-R achieves ~63,998 msg/s in local computation, with ~13 µs per-message overhead vs. the fastest baseline. The paper should frame this as acceptable overhead for extra recovery/security capability.

## Concurrency
Source: `paper_data/04_concurrency.csv`
| Clients | Mean Throughput | Mean RTT | Success Rate |
|---:|---:|---:|---:|
| 1 | 6,754 msg/s | 0.134 ms | 100.0% |
| 2 | 13,682 msg/s | 0.134 ms | 100.0% |
| 5 | 17,244 msg/s | 0.309 ms | 100.0% |
| 10 | 16,112 msg/s | 0.588 ms | 100.0% |
| 20 | 14,699 msg/s | 1.315 ms | 100.0% |

Throughput peaks at 5 concurrent client(s) and subsequently degrades at higher concurrency. The cause may involve server implementation characteristics, interpreter scheduling, and local resource contention; no performance profiling has been conducted to establish a definitive cause.

## Weak-Network Simulation
Source: `paper_data/05_weak_network.csv`
| Protocol | Mean Success Rate | Mean Throughput | Mean RTT |
|---|---:|---:|---:|
| GMCP-R | 100.0% | 462.8 msg/s | 0.3 ms |
| Hash Chain | 100.0% | 428.5 msg/s | 0.3 ms |
| Seq+MAC | 100.0% | 470.7 msg/s | 0.3 ms |

### Detailed Breakdown
| Protocol | Loss % | Delay ms | Success Rate | Throughput | RTT | Repeats |
|---|---:|---:|---:|---:|---:|---:|
| GMCP-R | 0 | 0 | 100.0% | 9,213.9 msg/s | 0.1 ms | 2 |
| GMCP-R | 0 | 20 | 100.0% | 41.6 msg/s | 0.4 ms | 2 |
| GMCP-R | 0 | 50 | 100.0% | 18.5 msg/s | 0.4 ms | 2 |
| GMCP-R | 0 | 100 | 100.0% | 9.6 msg/s | 0.4 ms | 2 |
| GMCP-R | 0 | 200 | 100.0% | 4.9 msg/s | 0.4 ms | 2 |
| GMCP-R | 1 | 0 | 100.0% | 1,439.9 msg/s | 0.1 ms | 2 |
| GMCP-R | 1 | 20 | 100.0% | 39.0 msg/s | 0.4 ms | 2 |
| GMCP-R | 1 | 50 | 100.0% | 18.1 msg/s | 0.4 ms | 2 |
| GMCP-R | 1 | 100 | 100.0% | 9.6 msg/s | 0.4 ms | 2 |
| GMCP-R | 1 | 200 | 100.0% | 4.8 msg/s | 0.4 ms | 2 |
| GMCP-R | 2 | 0 | 100.0% | 335.1 msg/s | 0.1 ms | 2 |
| GMCP-R | 2 | 20 | 100.0% | 37.1 msg/s | 0.4 ms | 2 |
| GMCP-R | 2 | 50 | 100.0% | 17.6 msg/s | 0.4 ms | 2 |
| GMCP-R | 2 | 100 | 100.0% | 9.1 msg/s | 0.4 ms | 2 |
| GMCP-R | 2 | 200 | 100.0% | 4.6 msg/s | 0.4 ms | 2 |
| GMCP-R | 5 | 0 | 100.0% | 195.3 msg/s | 0.2 ms | 2 |
| GMCP-R | 5 | 20 | 100.0% | 30.3 msg/s | 0.4 ms | 2 |
| GMCP-R | 5 | 50 | 100.0% | 15.9 msg/s | 0.4 ms | 2 |
| GMCP-R | 5 | 100 | 100.0% | 8.3 msg/s | 0.4 ms | 2 |
| GMCP-R | 5 | 200 | 100.0% | 4.4 msg/s | 0.4 ms | 2 |
| GMCP-R | 10 | 0 | 100.0% | 61.7 msg/s | 0.2 ms | 2 |
| GMCP-R | 10 | 20 | 100.0% | 26.1 msg/s | 0.4 ms | 2 |
| GMCP-R | 10 | 50 | 100.0% | 13.7 msg/s | 0.4 ms | 2 |
| GMCP-R | 10 | 100 | 100.0% | 7.7 msg/s | 0.4 ms | 2 |
| GMCP-R | 10 | 200 | 100.0% | 4.2 msg/s | 0.4 ms | 2 |
| Hash Chain | 0 | 0 | 100.0% | 8,646.5 msg/s | 0.1 ms | 2 |
| Hash Chain | 0 | 20 | 100.0% | 37.6 msg/s | 0.3 ms | 2 |
| Hash Chain | 0 | 50 | 100.0% | 17.5 msg/s | 0.3 ms | 2 |
| Hash Chain | 0 | 100 | 100.0% | 9.3 msg/s | 0.3 ms | 2 |
| Hash Chain | 0 | 200 | 100.0% | 4.8 msg/s | 0.3 ms | 2 |
| Hash Chain | 1 | 0 | 100.0% | 1,102.6 msg/s | 0.1 ms | 2 |
| Hash Chain | 1 | 20 | 100.0% | 35.2 msg/s | 0.3 ms | 2 |
| Hash Chain | 1 | 50 | 100.0% | 17.0 msg/s | 0.4 ms | 2 |
| Hash Chain | 1 | 100 | 100.0% | 9.3 msg/s | 0.3 ms | 2 |
| Hash Chain | 1 | 200 | 100.0% | 4.7 msg/s | 0.4 ms | 2 |
| Hash Chain | 2 | 0 | 100.0% | 391.4 msg/s | 0.1 ms | 2 |
| Hash Chain | 2 | 20 | 100.0% | 33.8 msg/s | 0.3 ms | 2 |
| Hash Chain | 2 | 50 | 100.0% | 17.0 msg/s | 0.3 ms | 2 |
| Hash Chain | 2 | 100 | 100.0% | 9.1 msg/s | 0.3 ms | 2 |
| Hash Chain | 2 | 200 | 100.0% | 4.7 msg/s | 0.3 ms | 2 |
| Hash Chain | 5 | 0 | 100.0% | 168.1 msg/s | 0.1 ms | 2 |
| Hash Chain | 5 | 20 | 100.0% | 29.6 msg/s | 0.3 ms | 2 |
| Hash Chain | 5 | 50 | 100.0% | 15.1 msg/s | 0.3 ms | 2 |
| Hash Chain | 5 | 100 | 100.0% | 8.5 msg/s | 0.3 ms | 2 |
| Hash Chain | 5 | 200 | 100.0% | 4.5 msg/s | 0.3 ms | 2 |
| Hash Chain | 10 | 0 | 100.0% | 96.7 msg/s | 0.2 ms | 2 |
| Hash Chain | 10 | 20 | 100.0% | 24.1 msg/s | 0.4 ms | 2 |
| Hash Chain | 10 | 50 | 100.0% | 13.9 msg/s | 0.3 ms | 2 |
| Hash Chain | 10 | 100 | 100.0% | 8.0 msg/s | 0.4 ms | 2 |
| Hash Chain | 10 | 200 | 100.0% | 4.1 msg/s | 0.3 ms | 2 |
| Seq+MAC | 0 | 0 | 100.0% | 9,922.5 msg/s | 0.1 ms | 2 |
| Seq+MAC | 0 | 20 | 100.0% | 38.0 msg/s | 0.3 ms | 2 |
| Seq+MAC | 0 | 50 | 100.0% | 17.5 msg/s | 0.3 ms | 2 |
| Seq+MAC | 0 | 100 | 100.0% | 9.5 msg/s | 0.3 ms | 2 |
| Seq+MAC | 0 | 200 | 100.0% | 4.8 msg/s | 0.3 ms | 2 |
| Seq+MAC | 1 | 0 | 100.0% | 717.7 msg/s | 0.1 ms | 2 |
| Seq+MAC | 1 | 20 | 100.0% | 34.7 msg/s | 0.3 ms | 2 |
| Seq+MAC | 1 | 50 | 100.0% | 16.8 msg/s | 0.3 ms | 2 |
| Seq+MAC | 1 | 100 | 100.0% | 9.0 msg/s | 0.3 ms | 2 |
| Seq+MAC | 1 | 200 | 100.0% | 4.8 msg/s | 0.3 ms | 2 |
| Seq+MAC | 2 | 0 | 100.0% | 572.2 msg/s | 0.1 ms | 2 |
| Seq+MAC | 2 | 20 | 100.0% | 34.6 msg/s | 0.3 ms | 2 |
| Seq+MAC | 2 | 50 | 100.0% | 17.1 msg/s | 0.3 ms | 2 |
| Seq+MAC | 2 | 100 | 100.0% | 9.0 msg/s | 0.3 ms | 2 |
| Seq+MAC | 2 | 200 | 100.0% | 4.6 msg/s | 0.3 ms | 2 |
| Seq+MAC | 5 | 0 | 100.0% | 152.9 msg/s | 0.1 ms | 2 |
| Seq+MAC | 5 | 20 | 100.0% | 30.6 msg/s | 0.3 ms | 2 |
| Seq+MAC | 5 | 50 | 100.0% | 16.4 msg/s | 0.3 ms | 2 |
| Seq+MAC | 5 | 100 | 100.0% | 8.1 msg/s | 0.3 ms | 2 |
| Seq+MAC | 5 | 200 | 100.0% | 4.4 msg/s | 0.3 ms | 2 |
| Seq+MAC | 10 | 0 | 100.0% | 95.4 msg/s | 0.2 ms | 2 |
| Seq+MAC | 10 | 20 | 100.0% | 22.7 msg/s | 0.3 ms | 2 |
| Seq+MAC | 10 | 50 | 100.0% | 13.4 msg/s | 0.3 ms | 2 |
| Seq+MAC | 10 | 100 | 100.0% | 7.7 msg/s | 0.3 ms | 2 |
| Seq+MAC | 10 | 200 | 100.0% | 4.0 msg/s | 0.4 ms | 2 |

**Note**: This is a **code-level simulation** (artificial `time.sleep` delays
and random message drops in the client code), not a real `tc/netem` or ns-3
network emulation. Results should not be presented as real weak-network
performance.
All protocols achieve 100% success in the lossless control group (loss=0, delay=0).
Under lossy conditions (loss>0), GMCP-R achieves the highest mean success rate at 100.0%.

## MemoryTicket Recovery
Source: `paper_data/06_memory_ticket_recovery.csv`
| Scenario | Rows | Recovery Success | Full Recovery | Memory Match |
|---|---:|---:|---:|---:|
| `disconnect` | 180 | 180 (100.0%) | 180 (100.0%) | 180 (100.0%) |
| `drop` | 180 | 180 (100.0%) | 180 (100.0%) | 180 (100.0%) |
| `modify` | 180 | 180 (100.0%) | 180 (100.0%) | 180 (100.0%) |
| `prev_mem` | 180 | 180 (100.0%) | 180 (100.0%) | 180 (100.0%) |
| `replay` | 180 | 180 (100.0%) | 180 (100.0%) | 180 (100.0%) |

All 900 recovery scenarios achieve 100% success rate, full recovery, and memory match after recovery.

## Checkpoint Recovery
Source: `paper_data/07_checkpoint_recovery.csv`
| Checkpoint Interval (k) | Rows | Recovery Success | Memory Match | Avg Replay Count |
|---:|---:|---:|---:|---:|
| 50 | 60 | 60 (100.0%) | 60 (100.0%) | 49.0 |
| 100 | 60 | 60 (100.0%) | 60 (100.0%) | 49.0 |

Checkpoint recovery replays only the messages since the last checkpoint, demonstrating O(k) recovery cost.

## Recovery Window
Source: `paper_data/08_recovery_window.csv`
| Scenario | Rows | Success | Expected |
|---|---:|---:|---:|
| `ack_loss` | 180 | 180 (100.0%) | Accept |
| `below_floor` | 180 | 0 (0.0%) | Reject (rollback) |
| `control` | 180 | 180 (100.0%) | Accept |
| `nonce_race` | 40 | 40 (100.0%) | Accept (1 winner) |
| `old_ticket_within_window` | 180 | 180 (100.0%) | Accept |

The `below_floor` scenario is correctly rejected because the ticket's `last_seq` is older than the server's required recovery floor. The `nonce_race` scenario has exactly 1 winner per run (duplicate nonces are rejected as replays).

## Checkpoint Cost: O(k) vs O(n)
Source: `paper_data/09_checkpoint_cost.csv`
| n | k | Protocol | Recovery Time | Replay Count | Material Size |
|---:|---:|---|---:|---:|---:|
| 1,000 | 10 | Authenticated Hash Chain | 9.90 ms | 995 | 516,776 B |
| 1,000 | 10 | GMCP-R | 0.27 ms | 5 | 2,430 B |
| 1,000 | 50 | Authenticated Hash Chain | 9.95 ms | 975 | 506,386 B |
| 1,000 | 50 | GMCP-R | 0.45 ms | 25 | 11,018 B |
| 1,000 | 100 | Authenticated Hash Chain | 9.68 ms | 950 | 494,347 B |
| 1,000 | 100 | GMCP-R | 0.77 ms | 50 | 21,804 B |
| 1,000 | 500 | Authenticated Hash Chain | 8.08 ms | 750 | 390,222 B |
| 1,000 | 500 | GMCP-R | 2.57 ms | 250 | 107,884 B |
| 10,000 | 10 | Authenticated Hash Chain | 110.63 ms | 9,995 | 5,221,048 B |
| 10,000 | 10 | GMCP-R | 0.27 ms | 5 | 2,449 B |
| 10,000 | 50 | Authenticated Hash Chain | 102.77 ms | 9,975 | 5,210,605 B |
| 10,000 | 50 | GMCP-R | 0.44 ms | 25 | 11,097 B |
| 10,000 | 100 | Authenticated Hash Chain | 100.84 ms | 9,950 | 5,207,495 B |
| 10,000 | 100 | GMCP-R | 0.64 ms | 50 | 21,958 B |
| 10,000 | 500 | Authenticated Hash Chain | 103.98 ms | 9,750 | 5,102,784 B |
| 10,000 | 500 | GMCP-R | 2.61 ms | 250 | 108,638 B |
| 100,000 | 10 | Authenticated Hash Chain | 1001.59 ms | 99,995 | 52,534,212 B |
| 100,000 | 10 | GMCP-R | 0.27 ms | 5 | 2,468 B |
| 100,000 | 50 | Authenticated Hash Chain | 1018.80 ms | 99,975 | 52,523,563 B |
| 100,000 | 50 | GMCP-R | 0.46 ms | 25 | 11,176 B |
| 100,000 | 100 | Authenticated Hash Chain | 1014.68 ms | 99,950 | 52,610,466 B |
| 100,000 | 100 | GMCP-R | 0.67 ms | 50 | 22,112 B |
| 100,000 | 500 | Authenticated Hash Chain | 1007.09 ms | 99,750 | 52,505,126 B |
| 100,000 | 500 | GMCP-R | 2.45 ms | 250 | 109,392 B |

GMCP-R recovers in O(k) time regardless of chain length n. For n=100,000 and k=10, GMCP-R is ~3771× faster than Authenticated Hash Chain (which must scan the entire chain in O(n)).

## Limitations
1. **Weak-network results are code-level simulation only.** The delays and
   packet drops are injected in Python client code via `time.sleep` and
   random skip logic. These are not real network impairments. A `tc/netem`
   or ns-3 experiment is needed before making deployment claims.

2. **Single-machine loopback.** All TCP experiments run on
   `127.0.0.1:9000/9001` (localhost). Cross-host latency, bandwidth
   constraints, and real packet loss are not captured.

3. **Repeat counts.** Most experiment configurations use 30 repeats.
   Weak-network uses only 2 repeats per configuration. Higher repeat
   counts would strengthen statistical claims.

4. **Prototype, not production.** The server is single-threaded Python.
   Throughput figures reflect cryptographic overhead, not production
   deployment characteristics.
