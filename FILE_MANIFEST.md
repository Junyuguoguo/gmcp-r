# GMCP-R 实验文件清单

**更新时间**：2026-07-03

---

## 📁 项目结构

```
gmcp_r/
├── gmcp/                              # 核心协议模块
│   ├── baselines/                     # Baseline协议实现
│   │   ├── hash_chain.py              # Hash Chain协议
│   │   ├── seq_mac.py                 # Sequential MAC协议
│   │   └── ticket_only.py             # Ticket Only协议
│   ├── checkpoint_manager.py          # Checkpoint管理器
│   ├── config.py                      # 配置文件
│   ├── crypto_utils.py                # 加密工具
│   ├── experiment_stats.py            # 实验统计模块
│   ├── memory.py                      # 记忆链管理
│   ├── packet.py                      # 数据包构建
│   ├── protocol.py                    # GMCP-R协议核心
│   ├── statistical_analysis.py        # 统计分析模块
│   └── ticket.py                      # MemoryTicket
│
├── experiments/                       # 实验脚本
│   ├── run_real_baseline_comparison.py    # Baseline对比实验
│   ├── run_weak_network_simulation.py     # 弱网仿真实验
│   ├── run_concurrent_experiment.py       # 并发测试
│   ├── run_performance_benchmark.py       # 性能基准测试
│   └── run_real_tc_netem_experiment.py    # tc/netem弱网实验（需要服务器）
│
├── servers/                           # 服务器脚本
│   ├── real_baseline_server.py        # Baseline对比服务器（端口9001）
│   ├── real_tcp_server.py             # GMCP-R服务器（端口9000）
│   └── real_tcp_server_with_ticket.py # 带MemoryTicket的服务器
│
├── plotting/                          # 绘图脚本
│   ├── plot_real_baseline_comparison.py
│   ├── plot_weak_network_simulation.py
│   ├── plot_concurrent_results.py
│   ├── plot_performance_results.py
│   └── generate_latex_tables.py
│
├── results/                           # 实验结果
│   ├── real_baseline_comparison/      # Baseline对比结果
│   │   ├── real_baseline_comparison_results.csv
│   │   ├── summary_real_baseline_comparison.csv
│   │   ├── statistical_report.txt
│   │   └── figures/
│   ├── performance/                   # 性能基准结果
│   │   ├── performance_benchmark_results.csv
│   │   └── figures/
│   ├── concurrent/                    # 并发测试结果
│   │   ├── concurrent_results.csv
│   │   ├── concurrent_detail.csv
│   │   └── figures/
│   └── weak_network_simulation/       # 弱网仿真结果（进行中）
│       ├── weak_network_simulation_results.csv
│       └── figures/
│
├── docs/                              # 文档
│   ├── security_analysis.md           # 安全性分析
│   ├── threat_model.md                # 威胁模型
│   └── experiment_methodology.md      # 实验方法论
│
├── paper/                             # 论文
│   ├── main.tex                       # LaTeX主文件
│   ├── references.bib                 # 参考文献
│   ├── figures/                       # 论文图表
│   ├── tables/                        # LaTeX表格
│   ├── COMPILATION_GUIDE.md           # 编译指南
│   └── SUBMISSION_CHECKLIST.md        # 提交清单
│
├── SCI_EXPERIMENT_PLAN.md             # 实验计划
├── EXPERIMENT_GUIDE.md                # 实验指南
├── QUICK_REFERENCE.md                 # 快速参考
└── experiment_dashboard.py            # 实验监控面板
```

---

## 📊 实验数据统计

| 实验 | 数据行数 | 状态 | 说明 |
|------|----------|------|------|
| Baseline对比 | 3,600 | ✅ 完成 | 4种协议，repeat=30 |
| 性能基准 | 120 | ✅ 完成 | 本地测试 |
| 并发测试 | 15 | ✅ 完成 | 1-20个客户端 |
| 弱网仿真 | 进行中 | 🔄 运行中 | 96种配置 |

---

## 🎯 论文准备状态

| 项目 | 状态 |
|------|------|
| ✅ 实验设计 | 完成 |
| ✅ 实验实现 | 完成 |
| ✅ 实验运行 | 3,735+个实验 |
| ✅ 统计分析 | ANOVA, t-test, CI |
| ✅ 图表生成 | 600dpi，期刊级 |
| ✅ 论文撰写 | LaTeX格式 |
| ✅ 并发测试 | 完成 |
| 🔄 弱网仿真 | 进行中 |

---

**最后更新**：2026-07-03
