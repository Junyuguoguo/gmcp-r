# GMCP-R Experiment Guide

## Experiment Groups

1. Protocol baseline comparison: `run_baseline_comparison_experiment.py`
2. Real TCP two-end memory communication: `run_real_tcp_network_experiment.py`
3. Sliding-window memory optimization: plotted from real TCP results by `plot_real_memory_results.py`
4. Real TCP attack recovery: `run_real_recovery_experiment.py`
5. Controlled weak-network simulation: `run_weak_network_experiment.py`
6. MemoryTicket security: `run_ticket_security_experiment.py`

## Real TCP Experiments

These experiments require `real_tcp_server.py` running on the target host:

- `run_real_tcp_network_experiment.py`
- `run_real_recovery_experiment.py`

Start the real server:

```bash
GMCP_BIND_HOST=0.0.0.0 GMCP_PORT=9000 python real_tcp_server.py
```

Run real experiments from the client machine:

```bash
GMCP_REPEATS=3 GMCP_TARGET_HOST=38.76.169.74 GMCP_PORT=9000 python run_real_tcp_network_experiment.py
python plot_real_network_results.py
python plot_real_memory_results.py

GMCP_REPEATS=3 GMCP_TARGET_HOST=38.76.169.74 GMCP_PORT=9000 python run_real_recovery_experiment.py
python plot_real_recovery_results.py
```

`avg_rtt_ms`, `p50_rtt_ms`, and `p95_rtt_ms` are Application-level RTT values measured by request/response timing, not ICMP ping RTT.

## Protocol-Level Simulations

These experiments are analytical or controlled simulations, not real TCP measurements:

- `run_baseline_comparison_experiment.py`
- `run_weak_network_experiment.py`
- `run_ticket_security_experiment.py`

Run them:

```bash
python run_baseline_comparison_experiment.py
python plot_baseline_comparison_results.py

python run_weak_network_experiment.py
python plot_weak_network_results.py

python run_ticket_security_experiment.py
python plot_ticket_security_results.py
```

Fast mode is available for baseline and weak-network simulations:

```bash
GMCP_QUICK=1 python run_baseline_comparison_experiment.py
GMCP_QUICK=1 python run_weak_network_experiment.py
```

## Unified Scripts

Run protocol-level experiments, plots, validation, and report generation:

```bash
bash run_all_experiments.sh
```

Run real TCP experiments when the server is already available:

```bash
bash run_real_experiments.sh
```

If your shell does not provide `python`, set `PYTHON` explicitly:

```bash
PYTHON=.venv/bin/python bash run_all_experiments.sh
```

## Output Directories

- `results/baseline/`: baseline comparison CSV, summary, figures
- `results/real_network/`: real TCP memory communication CSV, summaries, figures
- `results/real_recovery/`: real attack recovery CSV, summary, figures
- `results/weak_network/`: controlled weak-network simulation CSV, summary, figures
- `results/ticket_security/`: MemoryTicket security CSV, summary, figures
- `results/report/`: generated Markdown summary and selected figure list

## Validation and Report

Validate key result files and metrics:

```bash
python validate_experiment_results.py
```

Generate report-ready Markdown:

```bash
python generate_experiment_report.py
```

`validate_experiment_results.py` prints `MISSING` for experiments that have not been run. It does not crash just because real TCP results are absent.
