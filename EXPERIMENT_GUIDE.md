# GMCP-R 实验运行指南

**更新时间**：2026-07-02

---

## 📋 实验概览

| 实验 | 脚本 | 说明 | 预计时间 |
|------|------|------|----------|
| Baseline对比 | `run_real_baseline_comparison.py` | 对比GMCP-R与3种baseline | 2-4小时 |
| 真实Ticket恢复 | `run_real_ticket_recovery_experiment.py` | 测试5种ticket攻击 | 1-2小时 |
| Checkpoint恢复 | `run_checkpoint_recovery_experiment.py` | 测试checkpoint机制 | 1小时 |
| 弱网实验 | `run_tc_netem_experiment.py` | tc/netem弱网测试 | 2-3小时 |

---

## 🚀 快速开始

### 1. 环境准备

```bash
# 进入项目目录
cd /Users/a0000/Desktop/实验/gmcp_r

# 安装依赖
pip install numpy scipy matplotlib
```

### 2. 启动服务器

```bash
# 启动baseline对比服务器（端口9001）
python3 real_baseline_server.py

# 或启动带ticket的服务器（端口9000）
python3 real_tcp_server_with_ticket.py
```

### 3. 运行实验

```bash
# 运行baseline对比实验
python3 run_real_baseline_comparison.py

# 运行ticket恢复实验
python3 run_real_ticket_recovery_experiment.py
```

### 4. 生成图表

```bash
# 生成baseline对比图表
python3 plot_real_baseline_comparison.py

# 生成ticket恢复图表
python3 plot_ticket_recovery_results.py
```

---

## 📊 实验详细说明

### 实验1：Baseline对比实验

**目的**：对比GMCP-R与hash_chain、seq_mac、ticket_only协议的性能

**参数**：
- 协议：gmcp_r, hash_chain, seq_mac, ticket_only
- 消息数量：100, 500, 1000
- 负载大小：128, 512 bytes
- 攻击类型：none, drop, modify, replay, prev_mem
- 重复次数：5（可设置环境变量GMCP_REPEATS）

**运行**：
```bash
# 设置重复次数
export GMCP_REPEATS=10

# 运行实验
python3 run_real_baseline_comparison.py
```

**输出**：
- CSV文件：`results/real_baseline_comparison/real_baseline_comparison_results.csv`
- 图表：`results/real_baseline_comparison/figures/`

---

### 实验2：真实Ticket恢复实验

**目的**：测试MemoryTicket在5种攻击场景下的恢复能力

**攻击类型**：
1. expired_ticket - 过期ticket
2. replayed_ticket - 重放ticket
3. tampered_ticket - 篡改ticket
4. rollback_ticket - 回滚ticket
5. wrong_session_ticket - 错误会话ticket

**运行**：
```bash
python3 run_real_ticket_recovery_experiment.py
```

**输出**：
- CSV文件：`results/real_ticket_recovery/real_ticket_recovery_results.csv`
- 图表：`results/real_ticket_recovery/figures/`

---

### 实验3：Checkpoint恢复实验

**目的**：测试基于Checkpoint的恢复机制

**参数**：
- Checkpoint间隔：100条消息
- 恢复策略：从最近Checkpoint回放

**运行**：
```bash
python3 run_checkpoint_recovery_experiment.py
```

---

### 实验4：真实弱网实验（需要服务器权限）

**目的**：使用tc/netem模拟真实弱网环境

**参数**：
- 丢包率：0%, 1%, 5%, 10%
- 延迟：0ms, 50ms, 100ms, 200ms
- 乱序率：0%, 5%, 10%

**运行**：
```bash
# 需要sudo权限
sudo python3 run_tc_netem_experiment.py
```

---

## 📈 统计分析

### 使用统计分析模块

```python
from gmcp.statistical_analysis import (
    calculate_mean_std_ci,
    t_test_two_samples,
    anova_one_way,
    generate_statistical_report,
)

# 示例：计算置信区间
data = [100, 102, 98, 101, 99, 103, 97, 100, 101, 99]
result = calculate_mean_std_ci(data)
print(f"Mean: {result['mean']:.2f}")
print(f"95% CI: [{result['ci_lower']:.2f}, {result['ci_upper']:.2f}]")

# 示例：t检验
sample1 = [100, 102, 98, 101, 99]
sample2 = [110, 112, 108, 111, 109]
t_result = t_test_two_samples(sample1, sample2)
print(f"p-value: {t_result['p_value']:.4f}")
print(f"Significant: {t_result['significant']}")
```

### 生成统计报告

```python
from gmcp.statistical_analysis import generate_statistical_report

groups = {
    "GMCP-R": [180, 182, 178, 181, 179],
    "Hash Chain": [250, 252, 248, 251, 249],
    "Seq+MAC": [150, 152, 148, 151, 149],
}

report = generate_statistical_report(groups, "statistical_report.txt")
print(report)
```

---

## 🎨 使用Academic Figures生成图表

### 安装

```bash
# academic-figures已安装在 ~/.hermes/skills/academic-figures/
```

### 生成柱状图

```bash
python3 ~/.hermes/skills/academic-figures/scripts/gen_figure.py \
  -t bar \
  -d your_data.json \
  -o figure.png \
  --theme okabe-ito \
  --title "Recovery Latency Comparison" \
  --ylabel "Latency (ms)" \
  --show-values
```

### 数据格式（JSON）

```json
{
  "labels": ["GMCP-R", "Hash Chain", "Seq+MAC", "Ticket Only"],
  "series": {
    "Recovery Latency": [180, 250, 150, 160]
  },
  "errors": {
    "Recovery Latency": [20, 30, 15, 18]
  }
}
```

---

## 📁 输出文件结构

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
├── real_ticket_recovery/
│   ├── real_ticket_recovery_results.csv
│   └── figures/
├── checkpoint_recovery/
│   ├── checkpoint_recovery_results.csv
│   └── figures/
└── tc_netem/
    ├── tc_netem_results.csv
    └── figures/
```

---

## ⚠️ 注意事项

1. **服务器连接**：确保服务器（38.76.169.74）正在运行
2. **端口冲突**：baseline服务器使用9001端口，避免与现有服务器冲突
3. **重复次数**：SCI论文建议至少30次重复
4. **统计显著性**：使用t-test和ANOVA验证结果
5. **图表格式**：使用600dpi PNG或PDF格式（期刊要求）

---

## 🔧 故障排除

### 问题1：连接服务器失败

```bash
# 检查服务器状态
ping 38.76.169.74

# 检查端口
nc -zv 38.76.169.74 9000
nc -zv 38.76.169.74 9001
```

### 问题2：导入模块失败

```bash
# 确保在项目目录下运行
cd /Users/a0000/Desktop/实验/gmcp_r

# 检查Python路径
python3 -c "import gmcp; print('OK')"
```

### 问题3：图表生成失败

```bash
# 检查matplotlib
python3 -c "import matplotlib; print(matplotlib.__version__)"

# 检查字体
python3 -c "import matplotlib.font_manager; print('OK')"
```

---

## 📚 参考资料

- [SCI实验计划](SCI_EXPERIMENT_PLAN.md)
- [实验进展汇报](results/report/实验进展汇报.md)
- [Academic Writing Refiner](~/.hermes/skills/academic-writing-refiner/SKILL.md)
- [Academic Figures](~/.hermes/skills/academic-figures/SKILL.md)

---

**最后更新**：2026-07-02
