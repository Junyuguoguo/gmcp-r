#!/usr/bin/env bash
set -e

PYTHON_BIN="${PYTHON:-python}"

"$PYTHON_BIN" run_baseline_comparison_experiment.py
"$PYTHON_BIN" plot_baseline_comparison_results.py

"$PYTHON_BIN" run_weak_network_experiment.py
"$PYTHON_BIN" plot_weak_network_results.py

"$PYTHON_BIN" run_ticket_security_experiment.py
"$PYTHON_BIN" plot_ticket_security_results.py

"$PYTHON_BIN" validate_experiment_results.py
"$PYTHON_BIN" generate_experiment_report.py

# Real TCP experiments require real_tcp_server.py running on the server.
# Use run_real_experiments.sh for real_network and real_recovery.
