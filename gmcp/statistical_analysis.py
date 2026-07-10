# -*- coding: utf-8 -*-
# gmcp/statistical_analysis.py
#
# 统计分析模块 (SciPy-optional)
# 提供t-test、ANOVA、置信区间等统计检验
# CI functions delegate to gmcp.experiment_stats (no-SciPy).
# Advanced tests (t-test, ANOVA, Tukey) require SciPy at runtime.

import math
from typing import List, Dict, Any, Tuple, Optional

import numpy as np

# SciPy is optional — advanced tests raise RuntimeError when absent.
try:
    from scipy import stats as sp_stats
    _HAS_SCIPY = True
except ImportError:
    _HAS_SCIPY = False

from gmcp.experiment_stats import calculate_statistics, _student_t_critical


def _require_scipy(feature_name: str):
    """Raise RuntimeError if SciPy is not available."""
    if not _HAS_SCIPY:
        raise RuntimeError(
            f"SciPy is required for {feature_name}. "
            "Install it with: pip install scipy"
        )


def calculate_confidence_interval(
    data: List[float],
    confidence: float = 0.95
) -> Tuple[float, float, float]:
    """
    计算置信区间 — delegates to gmcp.experiment_stats (no-SciPy).

    参数：
    - data: 数据列表
    - confidence: 置信水平（默认95%）

    返回：
    - mean: 均值
    - ci_lower: 置信区间下界
    - ci_upper: 置信区间上界
    """
    if not data:
        return 0.0, 0.0, 0.0

    s = calculate_statistics(data, confidence)
    return s["mean"], s["mean"] - s["ci_half"], s["mean"] + s["ci_half"]


def calculate_mean_std_ci(
    data: List[float],
    confidence: float = 0.95
) -> Dict[str, float]:
    """
    计算均值、标准差和置信区间 — delegates to gmcp.experiment_stats.

    返回字典包含：
    - mean: 均值
    - std: 标准差
    - ci_lower: 置信区间下界
    - ci_upper: 置信区间上界
    - n: 样本数
    - margin_of_error: 误差范围
    """
    if not data:
        return {
            "mean": 0.0,
            "std": 0.0,
            "ci_lower": 0.0,
            "ci_upper": 0.0,
            "n": 0,
            "margin_of_error": 0.0,
        }

    s = calculate_statistics(data, confidence)

    return {
        "mean": s["mean"],
        "std": s["std"],
        "ci_lower": s["mean"] - s["ci_half"],
        "ci_upper": s["mean"] + s["ci_half"],
        "n": s["n"],
        "margin_of_error": s["ci_half"],
    }


def t_test_two_samples(
    sample1: List[float],
    sample2: List[float],
    alternative: str = 'two-sided'
) -> Dict[str, Any]:
    """
    双样本t检验 — requires SciPy.

    参数：
    - sample1: 样本1
    - sample2: 样本2
    - alternative: 替代假设 ('two-sided', 'less', 'greater')

    返回：
    - t_statistic: t统计量
    - p_value: p值
    - significant: 是否显著（p < 0.05）
    - effect_size: 效应量（Cohen's d）
    - interpretation: 结果解释
    """
    _require_scipy("two-sample t-test")

    if not sample1 or not sample2:
        return {
            "t_statistic": 0.0,
            "p_value": 1.0,
            "significant": False,
            "effect_size": 0.0,
            "interpretation": "Insufficient data",
        }

    arr1 = np.array(sample1)
    arr2 = np.array(sample2)

    # 执行t检验
    t_stat, p_value = sp_stats.ttest_ind(arr1, arr2, alternative=alternative)

    # 计算Cohen's d（效应量）
    n1, n2 = len(arr1), len(arr2)
    var1, var2 = np.var(arr1, ddof=1), np.var(arr2, ddof=1)
    pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_std == 0:
        effect_size = 0.0
    else:
        effect_size = (np.mean(arr1) - np.mean(arr2)) / pooled_std

    # 解释效应量
    if abs(effect_size) < 0.2:
        effect_interpretation = "negligible"
    elif abs(effect_size) < 0.5:
        effect_interpretation = "small"
    elif abs(effect_size) < 0.8:
        effect_interpretation = "medium"
    else:
        effect_interpretation = "large"

    # 判断显著性
    significant = p_value < 0.05

    # 结果解释
    if significant:
        interpretation = f"Statistically significant (p={p_value:.4f}), {effect_interpretation} effect (d={effect_size:.2f})"
    else:
        interpretation = f"Not statistically significant (p={p_value:.4f})"

    return {
        "t_statistic": float(t_stat),
        "p_value": float(p_value),
        "significant": significant,
        "effect_size": float(effect_size),
        "effect_interpretation": effect_interpretation,
        "interpretation": interpretation,
    }


def anova_one_way(*samples: List[float]) -> Dict[str, Any]:
    """
    单因素方差分析（ANOVA） — requires SciPy.

    参数：
    - *samples: 多个样本组

    返回：
    - f_statistic: F统计量
    - p_value: p值
    - significant: 是否显著
    - eta_squared: 效应量（η²）
    - interpretation: 结果解释
    """
    _require_scipy("one-way ANOVA")

    if len(samples) < 2:
        return {
            "f_statistic": 0.0,
            "p_value": 1.0,
            "significant": False,
            "eta_squared": 0.0,
            "interpretation": "Need at least 2 groups",
        }

    # 过滤空样本
    valid_samples = [np.array(s) for s in samples if len(s) > 0]

    if len(valid_samples) < 2:
        return {
            "f_statistic": 0.0,
            "p_value": 1.0,
            "significant": False,
            "eta_squared": 0.0,
            "interpretation": "Insufficient valid groups",
        }

    # 执行ANOVA
    f_stat, p_value = sp_stats.f_oneway(*valid_samples)

    # 计算η²（效应量）
    all_data = np.concatenate(valid_samples)
    grand_mean = np.mean(all_data)

    ss_between = sum(len(s) * (np.mean(s) - grand_mean) ** 2 for s in valid_samples)
    ss_total = np.sum((all_data - grand_mean) ** 2)

    if ss_total == 0:
        eta_squared = 0.0
    else:
        eta_squared = ss_between / ss_total

    # 判断显著性
    significant = p_value < 0.05

    # 结果解释
    if significant:
        interpretation = f"Significant difference between groups (p={p_value:.4f}, η²={eta_squared:.3f})"
    else:
        interpretation = f"No significant difference between groups (p={p_value:.4f})"

    return {
        "f_statistic": float(f_stat),
        "p_value": float(p_value),
        "significant": significant,
        "eta_squared": float(eta_squared),
        "interpretation": interpretation,
    }


def post_hoc_tukey(*samples: List[float]) -> Dict[str, Any]:
    """
    Tukey HSD事后检验 — requires SciPy.

    参数：
    - *samples: 多个样本组

    返回：
    - pairwise_comparisons: 两两比较结果
    """
    _require_scipy("Tukey HSD post-hoc test")

    if len(samples) < 2:
        return {"pairwise_comparisons": []}

    # 过滤空样本
    valid_samples = [np.array(s) for s in samples if len(s) > 0]

    if len(valid_samples) < 2:
        return {"pairwise_comparisons": []}

    # 执行Tukey HSD
    result = sp_stats.tukey_hsd(*valid_samples)

    comparisons = []
    n_groups = len(valid_samples)

    for i in range(n_groups):
        for j in range(i + 1, n_groups):
            comparisons.append({
                "group1": i,
                "group2": j,
                "mean_diff": float(np.mean(valid_samples[i]) - np.mean(valid_samples[j])),
                "p_value": float(result.pvalue[i][j]),
                "significant": result.pvalue[i][j] < 0.05,
            })

    return {"pairwise_comparisons": comparisons}


def calculate_descriptive_stats(data: List[float]) -> Dict[str, float]:
    """
    计算描述性统计 — uses NumPy only (no SciPy).

    返回：
    - n: 样本数
    - mean: 均值
    - std: 标准差
    - min: 最小值
    - max: 最大值
    - median: 中位数
    - q1: 第一四分位数
    - q3: 第三四分位数
    - iqr: 四分位距
    """
    if not data:
        return {
            "n": 0, "mean": 0, "std": 0, "min": 0, "max": 0,
            "median": 0, "q1": 0, "q3": 0, "iqr": 0,
        }

    arr = np.array(data)

    return {
        "n": len(arr),
        "mean": float(np.mean(arr)),
        "std": float(np.std(arr, ddof=1)) if len(arr) > 1 else 0.0,
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "median": float(np.median(arr)),
        "q1": float(np.percentile(arr, 25)),
        "q3": float(np.percentile(arr, 75)),
        "iqr": float(np.percentile(arr, 75) - np.percentile(arr, 25)),
    }


def format_statistical_results(
    data: List[float],
    label: str = "Metric"
) -> str:
    """
    格式化统计结果为可读字符串

    示例输出：
    "Metric: 45.2 ± 3.1 (95% CI: 42.1 - 48.3, n=30)"
    """
    s = calculate_mean_std_ci(data)

    return (f"{label}: {s['mean']:.2f} ± {s['std']:.2f} "
            f"(95% CI: {s['ci_lower']:.2f} - {s['ci_upper']:.2f}, "
            f"n={s['n']})")


def generate_statistical_report(
    groups: Dict[str, List[float]],
    output_file: Optional[str] = None
) -> str:
    """
    生成统计报告

    参数：
    - groups: 分组数据 {"group_name": [values]}
    - output_file: 输出文件路径（可选）

    返回：
    - 报告字符串
    """
    report = []
    report.append("=" * 80)
    report.append("Statistical Analysis Report")
    report.append("=" * 80)
    report.append("")

    # 描述性统计
    report.append("1. Descriptive Statistics")
    report.append("-" * 40)

    for group_name, values in groups.items():
        desc_stats = calculate_descriptive_stats(values)
        report.append(f"\n{group_name}:")
        report.append(f"  n = {desc_stats['n']}")
        report.append(f"  Mean ± Std = {desc_stats['mean']:.2f} ± {desc_stats['std']:.2f}")
        report.append(f"  Median = {desc_stats['median']:.2f}")
        report.append(f"  Range = [{desc_stats['min']:.2f}, {desc_stats['max']:.2f}]")
        report.append(f"  IQR = {desc_stats['iqr']:.2f}")

    report.append("")

    # 置信区间
    report.append("2. 95% Confidence Intervals")
    report.append("-" * 40)

    for group_name, values in groups.items():
        ci = calculate_mean_std_ci(values)
        report.append(f"{group_name}: {ci['mean']:.2f} ± {ci['margin_of_error']:.2f} "
                     f"(95% CI: {ci['ci_lower']:.2f} - {ci['ci_upper']:.2f})")

    report.append("")

    # ANOVA（如果有3个或更多组）
    if _HAS_SCIPY and len(groups) >= 3:
        report.append("3. One-Way ANOVA")
        report.append("-" * 40)

        anova_result = anova_one_way(*groups.values())
        report.append(f"F-statistic = {anova_result['f_statistic']:.4f}")
        report.append(f"p-value = {anova_result['p_value']:.4f}")
        report.append(f"η² = {anova_result['eta_squared']:.4f}")
        report.append(f"Interpretation: {anova_result['interpretation']}")

        report.append("")

    # 两两比较（t-test）
    if _HAS_SCIPY:
        report.append("4. Pairwise Comparisons (t-test)")
        report.append("-" * 40)

        group_names = list(groups.keys())
        for i in range(len(group_names)):
            for j in range(i + 1, len(group_names)):
                name1, name2 = group_names[i], group_names[j]
                t_result = t_test_two_samples(groups[name1], groups[name2])

                sig_marker = "***" if t_result['p_value'] < 0.001 else \
                            "**" if t_result['p_value'] < 0.01 else \
                            "*" if t_result['p_value'] < 0.05 else "ns"

                report.append(f"{name1} vs {name2}: "
                             f"t={t_result['t_statistic']:.3f}, "
                             f"p={t_result['p_value']:.4f} {sig_marker}, "
                             f"d={t_result['effect_size']:.2f} ({t_result['effect_interpretation']})")

        report.append("")
    else:
        report.append("3. Pairwise Comparisons (t-test)")
        report.append("-" * 40)
        report.append("  [Skipped — SciPy not installed]")
        report.append("")

    report.append("=" * 80)
    report.append("Legend: *** p<0.001, ** p<0.01, * p<0.05, ns = not significant")
    report.append("=" * 80)

    report_text = "\n".join(report)

    # 保存到文件
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(report_text)
        print(f"[STATS] Report saved to {output_file}")

    return report_text


# =========================
# 测试
# =========================

def demo_statistical_analysis():
    """演示统计分析功能"""
    print("=" * 60)
    print("Statistical Analysis Demo")
    print("=" * 60)

    # 示例数据
    np.random.seed(42)

    gmcp_r_latency = np.random.normal(180, 20, 30).tolist()
    hash_chain_latency = np.random.normal(250, 30, 30).tolist()
    seq_mac_latency = np.random.normal(150, 15, 30).tolist()
    ticket_only_latency = np.random.normal(160, 18, 30).tolist()

    groups = {
        "GMCP-R": gmcp_r_latency,
        "Hash Chain": hash_chain_latency,
        "Seq+MAC": seq_mac_latency,
        "Ticket Only": ticket_only_latency,
    }

    # 生成报告
    report = generate_statistical_report(groups)
    print(report)


if __name__ == "__main__":
    demo_statistical_analysis()
