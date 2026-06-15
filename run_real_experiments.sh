#!/usr/bin/env bash
set -e

PYTHON_BIN="${PYTHON:-python}"

"$PYTHON_BIN" run_real_tcp_network_experiment.py
"$PYTHON_BIN" plot_real_network_results.py
"$PYTHON_BIN" plot_real_memory_results.py

"$PYTHON_BIN" run_real_recovery_experiment.py
"$PYTHON_BIN" plot_real_recovery_results.py
