# -*- coding: utf-8 -*-
# generate_experiment_report.py

import csv
import os
from typing import Dict, List


REPORT_DIR = "results/report"
SUMMARY_MD = os.path.join(REPORT_DIR, "experiment_summary.md")
FIGURES_MD = os.path.join(REPORT_DIR, "selected_figures_list.md")


SUMMARY_PATHS = {
    "baseline": "results/baseline/summary_baseline_comparison.csv",
    "real_network": "results/real_network/summary_real_network.csv",
    "real_memory": "results/real_network/summary_real_memory.csv",
    "real_recovery": "results/real_recovery/summary_real_recovery.csv",
    "weak_network": "results/weak_network/summary_weak_network.csv",
    "ticket_security": "results/ticket_security/summary_ticket_security.csv",
}

SELECTED_FIGURES = [
    ("memory_fig1_memory_match_rate", "results/real_network/memory_figures/memory_fig1_memory_match_rate.png"),
    (
        "memory_fig3_prev_mem_detection_rate",
        "results/real_network/memory_figures/memory_fig3_prev_mem_detection_rate.png",
    ),
    ("memory_fig4_window_throughput", "results/real_network/memory_figures/memory_fig4_window_throughput.png"),
    (
        "memory_fig6_window_memory_match",
        "results/real_network/memory_figures/memory_fig6_window_memory_match.png",
    ),
    (
        "memory_fig8_attack_detection_rate",
        "results/real_network/memory_figures/memory_fig8_attack_detection_rate.png",
    ),
    (
        "recovery_fig1_success_rate_by_attack",
        "results/real_recovery/figures/recovery_fig1_success_rate_by_attack.png",
    ),
    (
        "recovery_fig2_latency_by_attack",
        "results/real_recovery/figures/recovery_fig2_latency_by_attack.png",
    ),
    (
        "recovery_fig3_memory_match_after_recovery",
        "results/real_recovery/figures/recovery_fig3_memory_match_after_recovery.png",
    ),
    (
        "baseline_fig1_recovery_latency_by_protocol",
        "results/baseline/figures/baseline_fig1_recovery_latency_by_protocol.png",
    ),
    (
        "baseline_fig2_memory_recovery_rate_by_protocol",
        "results/baseline/figures/baseline_fig2_memory_recovery_rate_by_protocol.png",
    ),
    (
        "baseline_fig4_secure_memory_recovery_success_by_protocol",
        "results/baseline/figures/baseline_fig4_secure_memory_recovery_success_by_protocol.png",
    ),
    (
        "baseline_fig7_checkpoint_interval_latency",
        "results/baseline/figures/baseline_fig7_checkpoint_interval_latency.png",
    ),
    (
        "weak_fig1_loss_rate_recovery_success",
        "results/weak_network/figures/weak_fig1_loss_rate_recovery_success.png",
    ),
    (
        "ticket_fig1_ticket_attack_detection_rate",
        "results/ticket_security/figures/ticket_fig1_ticket_attack_detection_rate.png",
    ),
]


def ensure_report_dir() -> None:
    os.makedirs(REPORT_DIR, exist_ok=True)


def read_summary(path: str) -> List[Dict[str, str]]:
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pct(value: str) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "N/A"


def first_value(rows: List[Dict[str, str]], key: str) -> str:
    if not rows:
        return "N/A"
    return rows[0].get(key, "N/A")


def generate_summary_markdown(summaries: Dict[str, List[Dict[str, str]]]) -> str:
    baseline_rows = summaries["baseline"]
    weak_rows = summaries["weak_network"]
    real_memory_rows = summaries["real_memory"]

    real_memory_match = pct(first_value(real_memory_rows, "normal_memory_match_rate"))
    real_prev_mem = pct(first_value(real_memory_rows, "prev_mem_detection_rate"))

    baseline_note = "baseline summary not available"
    if baseline_rows:
        gmcp_rows = [row for row in baseline_rows if row.get("protocol") == "gmcp_r"]
        hash_rows = [row for row in baseline_rows if row.get("protocol") == "hash_chain"]
        if gmcp_rows and hash_rows:
            baseline_note = (
                "GMCP-R keeps secure memory recovery while reducing modeled recovery latency "
                "and extra bytes compared with hash-chain replay."
            )

    weak_note = "weak_network summary not available"
    if weak_rows:
        weak_note = (
            "Controlled weak-network simulation separates loss, reordering, and delay. "
            "GMCP-R is expected to keep high memory match with lower recovery cost than hash_chain."
        )

    return "\n".join(
        [
            "# GMCP-R Experiment Summary",
            "",
            "## 1. 实验概览",
            "本项目实验体系分为 baseline 对比、真实 TCP 双端通信、滑动窗口优化、攻击后恢复、弱网/断续网络模拟、MemoryTicket 安全性六组。",
            "",
            "## 2. baseline 对比结论",
            baseline_note,
            "注意：baseline 是 protocol-level simulation，不是真实 TCP 网络实验。",
            "",
            "## 3. 真实双端通信结论",
            "真实 TCP 结果只来自 real_network 目录，需要 real_tcp_server.py 正在运行。",
            "",
            "## 4. 有记忆通信验证结论",
            f"当前 summary 中正常通信 memory match rate 为 {real_memory_match}，prev_mem detection rate 为 {real_prev_mem}。",
            "",
            "## 5. 滑动窗口优化结论",
            "window_size=1/5/10 的结果用于比较吞吐量、Application-level RTT 与 memory match 的权衡。",
            "",
            "## 6. 攻击后恢复结论",
            "real_recovery 结果验证攻击检测、RECOVERY_REQUEST/RECOVERY_RESPONSE、MemoryTicket 校验、同步恢复和最终记忆一致性。",
            "",
            "## 7. 弱网实验结论",
            weak_note,
            "注意：weak_network 是 controlled weak-network simulation，不是真实 TCP 网络实验。",
            "",
            "## 8. MemoryTicket 安全性结论",
            "ticket_security 实验覆盖 valid、expired、replayed、tampered、wrong_session、rollback 六类 ticket 场景。",
            "",
            "## 9. 当前不足",
            "协议级模拟的时延与吞吐分数来自确定性模型，不能替代跨地域真实网络测量；真实实验仍依赖服务器部署稳定性和单客户端场景。",
            "",
            "## 10. 后续改进方向",
            "建议补充多客户端并发、真实 tc/netem 弱网、跨云地域重复实验、更多 payload 分布、以及更接近生产密钥轮换的 ticket 生命周期测试。",
            "",
        ]
    )


def generate_figures_markdown() -> str:
    lines = [
        "# Selected Figures for Paper or Presentation",
        "",
        "The following figures are prioritized for the paper/report. Missing files mean the corresponding experiment or plot script has not been run yet.",
        "",
    ]
    for name, path in SELECTED_FIGURES:
        status = "exists" if os.path.exists(path) else "missing"
        lines.append(f"- `{name}`: `{path}` ({status})")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    ensure_report_dir()
    summaries = {name: read_summary(path) for name, path in SUMMARY_PATHS.items()}

    with open(SUMMARY_MD, "w", encoding="utf-8") as f:
        f.write(generate_summary_markdown(summaries))

    with open(FIGURES_MD, "w", encoding="utf-8") as f:
        f.write(generate_figures_markdown())

    print("[REPORT] summary saved to", SUMMARY_MD)
    print("[REPORT] selected figures saved to", FIGURES_MD)


if __name__ == "__main__":
    main()
