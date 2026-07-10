# GMCP-R Protocol: Quick Reference

## Experiment Commands

### Run Baseline Comparison

```bash
# Quick test (repeat=1)
export GMCP_REPEATS=1
python3.11 run_real_baseline_comparison.py

# Standard (repeat=5)
export GMCP_REPEATS=5
python3.11 run_real_baseline_comparison.py

# SCI quality (repeat=30)
export GMCP_REPEATS=30
python3.11 run_real_baseline_comparison.py
```

### Generate Charts

```bash
# Generate all charts
python3.11 plot_real_baseline_comparison.py

# Generate LaTeX tables
python3.11 generate_latex_tables.py
```

### Monitor Experiments

```bash
# Check progress
tail -f /tmp/baseline_experiment.log

# Monitor dashboard
python3.11 experiment_dashboard.py

# Check process
ps aux | grep run_real_baseline_comparison.py
```

## File Locations

### Code

```
gmcp_r/
├── gmcp/
│   ├── baselines/
│   │   ├── hash_chain.py
│   │   ├── seq_mac.py
│   │   └── ticket_only.py
│   ├── statistical_analysis.py
│   └── experiment_stats.py
├── real_baseline_server.py
├── run_real_baseline_comparison.py
└── plot_real_baseline_comparison.py
```

### Results

```
results/
├── real_baseline_comparison/
│   ├── real_baseline_comparison_results.csv
│   ├── summary_real_baseline_comparison.csv
│   └── figures/
│       ├── baseline_fig1_recovery_latency.png
│       ├── baseline_fig2_throughput.png
│       ├── baseline_fig3_attack_detection.png
│       ├── baseline_fig4_success_rate_heatmap.png
│       └── baseline_fig5_rtt_distribution.png
└── real_ticket_recovery/
    └── real_ticket_recovery_results.csv
```

### Documentation

```
docs/
├── security_analysis.md
├── threat_model.md
└── experiment_methodology.md

paper/
├── main.tex
├── references.bib
├── COMPILATION_GUIDE.md
└── SUBMISSION_CHECKLIST.md
```

## Key Metrics

### Performance

- **Throughput**: 8,000-13,000 msg/s
- **RTT**: 0.06-0.15 ms
- **Success Rate**: 100% (no attacks)

### Security

- **Attack Detection**: 100%
- **Recovery Success**: 100%
- **Memory Continuity**: Verified

### Statistical

- **Sample Size**: 30 repetitions
- **Confidence Level**: 95%
- **Significance**: p < 0.05

## Troubleshooting

### Issue: Server not starting

```bash
# Check if port is in use
lsof -i :9001

# Kill existing process
kill -9 <PID>
```

### Issue: Import errors

```bash
# Check Python version
python3.11 --version

# Install dependencies
pip install numpy scipy matplotlib
```

### Issue: CSV writing error

```bash
# Check file permissions
ls -la results/

# Create directory if missing
mkdir -p results/
```

## Contact

- **Author**: Junyu Wang
- **Email**: wangjunyu@bistu.edu.cn
- **Project**: GMCP-R Protocol

---

**Last Updated**: 2026-07-03
