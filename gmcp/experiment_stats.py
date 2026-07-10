# -*- coding: utf-8 -*-
# gmcp/experiment_stats.py
#
# 实验统计增强模块 (no-SciPy)
# 收集实验元数据，计算统计指标
# All statistics use only NumPy and the Python standard library.

import math
import os
import sys
import time
import uuid
import platform
import subprocess
from typing import Dict, Any, List, Optional, Sequence

try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False


# ============================================================
# Student-t critical values for 95% confidence (two-tailed α=0.05)
# _T95[df] = t_{α/2, df} for df = 1..30
# ============================================================

_T95: Dict[int, float] = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}


def _student_t_critical(df: int, confidence: float = 0.95) -> float:
    """
    Return the two-tailed Student-t critical value.

    Supports *confidence* = 0.95 only (raises ValueError otherwise).
    For df 1-30 uses an exact table; for df > 30 uses the normal
    approximation z_{α/2} = 1.960.
    """
    if not (0 < confidence < 1):
        raise ValueError(f"confidence must be in (0, 1), got {confidence}")
    if abs(confidence - 0.95) > 1e-9:
        raise ValueError(
            f"Only confidence=0.95 is supported without SciPy, got {confidence}"
        )
    if df < 1:
        raise ValueError(f"Degrees of freedom must be >= 1, got {df}")

    if df <= 30:
        return _T95[df]
    # Normal approximation for large df
    return 1.960


# ============================================================
# Core statistics (no-SciPy)
# ============================================================

def calculate_statistics(
    values: Sequence[float],
    confidence: float = 0.95,
) -> Dict[str, float]:
    """
    计算统计指标 without SciPy.

    返回：
    - mean: 均值
    - std: 样本标准差 (ddof=1)
    - ci_half: 置信区间半宽 (Student-t)
    - min: 最小值
    - max: 最大值
    - median: 中位数
    - n: 样本数

    兼容旧接口也返回 ci_95 键 (映射到 ci_half)。
    """
    if not values:
        return {
            "mean": 0.0, "std": 0.0, "ci_half": 0.0, "ci_95": 0.0,
            "min": 0.0, "max": 0.0, "median": 0.0, "n": 0,
        }

    n = len(values)

    if _HAS_NUMPY:
        arr = np.array(values, dtype=float)
        mean = float(np.mean(arr))
        std = float(np.std(arr, ddof=1)) if n > 1 else 0.0
        med = float(np.median(arr))
        mn = float(np.min(arr))
        mx = float(np.max(arr))
    else:
        mean = sum(values) / n
        if n > 1:
            variance = sum((v - mean) ** 2 for v in values) / (n - 1)
            std = math.sqrt(variance)
        else:
            std = 0.0
        sorted_vals = sorted(values)
        med = sorted_vals[n // 2] if n % 2 == 1 else (sorted_vals[n // 2 - 1] + sorted_vals[n // 2]) / 2.0
        mn = sorted_vals[0]
        mx = sorted_vals[-1]

    if n > 1:
        t_crit = _student_t_critical(n - 1, confidence)
        ci_half = t_crit * std / math.sqrt(n)
    else:
        ci_half = 0.0

    return {
        "mean": mean,
        "std": std,
        "ci_half": ci_half,
        "ci_95": ci_half,  # backward-compatible alias
        "min": mn,
        "max": mx,
        "median": med,
        "n": n,
    }


# ============================================================
# Observed rate with exact boundaries
# ============================================================

def calculate_observed_rate(
    success_count: int,
    total_count: int,
    confidence: float = 0.95,
) -> Dict[str, Any]:
    """
    计算观测成功率及置信区间。

    - All success (success == total): Clopper-Pearson exact lower bound
      ``lower = (1 - α)^(1/n)`` which equals ``0.025 ** (1/n)`` for 95%.
    - Zero success (success == 0): Symmetric upper = ``1 - 0.025 ** (1/n)``.
    - Otherwise: Wilson score interval.

    返回：
    - rate: 成功率
    - ci_lower: 下界
    - ci_upper: 上界
    - method: 使用的方法标识
    - success_count: 分子
    - total_count: 分母
    """
    if total_count == 0:
        return {
            "rate": 0.0, "ci_lower": 0.0, "ci_upper": 0.0,
            "method": "degenerate", "success_count": 0, "total_count": 0,
        }

    rate = success_count / total_count
    alpha = 1.0 - confidence  # 0.05 for 95%

    # All successes → Clopper-Pearson exact lower bound
    if success_count == total_count:
        lower = (alpha / 2.0) ** (1.0 / total_count)
        return {
            "rate": rate, "ci_lower": lower, "ci_upper": 1.0,
            "method": "clopper_pearson_exact_boundary",
            "success_count": success_count, "total_count": total_count,
        }

    # Zero successes → symmetric
    if success_count == 0:
        upper = 1.0 - (alpha / 2.0) ** (1.0 / total_count)
        return {
            "rate": 0.0, "ci_lower": 0.0, "ci_upper": upper,
            "method": "clopper_pearson_exact_boundary",
            "success_count": 0, "total_count": total_count,
        }

    # Intermediate → Wilson score interval
    z = _student_t_critical(total_count - 1, confidence) if total_count > 1 else 1.960
    # For large n, z ≈ 1.96; for small n use t quantile as approximation
    n = total_count
    denom = 1.0 + z * z / n
    centre = (rate + z * z / (2.0 * n)) / denom
    spread = z * math.sqrt((rate * (1.0 - rate) + z * z / (4.0 * n)) / n) / denom
    ci_lower = max(0.0, centre - spread)
    ci_upper = min(1.0, centre + spread)

    return {
        "rate": rate,
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "method": "wilson",
        "success_count": success_count,
        "total_count": total_count,
    }


# ============================================================
# Existing helpers (unchanged)
# ============================================================

def get_git_commit() -> str:
    """获取当前git commit hash"""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def get_python_version() -> str:
    """获取Python版本"""
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def get_os_info() -> str:
    """获取操作系统信息"""
    return f"{platform.system()} {platform.release()}"


def get_random_seed() -> Optional[int]:
    """获取当前随机种子（如果有的话）"""
    try:
        import random
        return random.getstate()[1][0]
    except Exception:
        return None


def get_command_line() -> str:
    """获取命令行参数"""
    return " ".join(sys.argv)


def generate_experiment_id() -> str:
    """生成唯一的实验ID"""
    timestamp = int(time.time() * 1000)
    random_part = uuid.uuid4().hex[:8]
    return f"exp-{timestamp}-{random_part}"


def generate_run_id() -> str:
    """生成唯一的运行ID"""
    return uuid.uuid4().hex[:12]


def collect_experiment_metadata() -> Dict[str, Any]:
    """收集实验元数据"""
    return {
        "experiment_id": generate_experiment_id(),
        "run_id": generate_run_id(),
        "git_commit": get_git_commit(),
        "python_version": get_python_version(),
        "os_info": get_os_info(),
        "random_seed": get_random_seed(),
        "command_line": get_command_line(),
        "experiment_type": "unknown",  # 由调用者设置
        "start_time": time.time(),
        "start_time_human": time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def calculate_rate(success_count: int, total_count: int) -> Dict[str, float]:
    """
    计算成功率及其置信区间 (Wilson score interval)

    返回：
    - rate: 成功率
    - ci_95_lower: 95%置信区间下界
    - ci_95_upper: 95%置信区间上界
    """
    if total_count == 0:
        return {
            "rate": 0.0,
            "ci_95_lower": 0.0,
            "ci_95_upper": 0.0,
        }

    rate = success_count / total_count

    # 使用Wilson score interval计算置信区间
    z = 1.96  # 95%置信区间
    denominator = 1 + z**2 / total_count
    centre_adjusted_probability = (rate + z * z / (2 * total_count)) / denominator
    adjusted_standard_deviation = math.sqrt((rate * (1 - rate) + z * z / (4 * total_count)) / total_count) / denominator

    ci_95_lower = max(0, centre_adjusted_probability - z * adjusted_standard_deviation)
    ci_95_upper = min(1, centre_adjusted_probability + z * adjusted_standard_deviation)

    return {
        "rate": rate,
        "ci_95_lower": ci_95_lower,
        "ci_95_upper": ci_95_upper,
    }


def calculate_security_metrics(
    false_accept_count: int,
    false_reject_count: int,
    total_legitimate: int,
    total_attack: int,
) -> Dict[str, float]:
    """
    计算安全指标

    返回：
    - false_accept_rate: 误接受率（攻击被接受）
    - false_reject_rate: 误拒绝率（合法被拒绝）
    - accuracy: 准确率
    """
    far = false_accept_count / total_attack if total_attack > 0 else 0.0
    frr = false_reject_count / total_legitimate if total_legitimate > 0 else 0.0
    accuracy = 1 - (far + frr) / 2

    return {
        "false_accept_rate": far,
        "false_reject_rate": frr,
        "accuracy": accuracy,
    }


def format_statistics_for_csv(
    values: List[float],
    prefix: str = "",
) -> Dict[str, Any]:
    """
    将统计指标格式化为CSV友好的格式

    返回一个字典，包含：
    - {prefix}_mean
    - {prefix}_std
    - {prefix}_ci_half (or {prefix}_ci_95 for compatibility)
    - {prefix}_min
    - {prefix}_max
    - {prefix}_median
    - {prefix}_n
    """
    s = calculate_statistics(values)

    result = {}
    for key, value in s.items():
        if key == "ci_95":
            # write ci_95 for backward compat
            k = f"{prefix}_ci_95" if prefix else "ci_95"
        elif key == "ci_half":
            k = f"{prefix}_ci_half" if prefix else "ci_half"
        else:
            k = f"{prefix}_{key}" if prefix else key
        result[k] = round(value, 4) if isinstance(value, float) else value

    return result


def add_metadata_to_csv_row(
    row: Dict[str, Any],
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """将元数据添加到CSV行"""
    result = dict(row)
    result.update(metadata)
    return result


def create_enhanced_csv_writer(fieldnames: List[str], metadata: Dict[str, Any]) -> List[str]:
    """创建增强的CSV字段列表（包含元数据字段）"""
    metadata_fields = [
        "experiment_id",
        "run_id",
        "git_commit",
        "python_version",
        "os_info",
        "random_seed",
        "command_line",
        "experiment_type",
    ]

    # 合并字段，去重
    all_fields = list(fieldnames)
    for field in metadata_fields:
        if field not in all_fields:
            all_fields.append(field)

    return all_fields


class ExperimentTracker:
    """
    实验跟踪器

    用于跟踪和记录实验的完整生命周期
    """

    def __init__(self, experiment_type: str):
        self.experiment_type = experiment_type
        self.metadata = collect_experiment_metadata()
        self.metadata["experiment_type"] = experiment_type

        self.results: List[Dict[str, Any]] = []
        self.start_time = time.time()

        # 性能监控
        self.cpu_samples: List[float] = []
        self.memory_samples: List[float] = []

    def add_result(self, result: Dict[str, Any]):
        """添加实验结果"""
        result_with_metadata = add_metadata_to_csv_row(result, self.metadata)
        self.results.append(result_with_metadata)

    def sample_performance(self):
        """采样性能指标"""
        try:
            import psutil
            self.cpu_samples.append(psutil.cpu_percent(interval=0.1))
            self.memory_samples.append(psutil.Process().memory_info().rss / 1024 / 1024)  # MB
        except ImportError:
            # psutil不可用，跳过
            pass

    def get_performance_stats(self) -> Dict[str, float]:
        """获取性能统计"""
        result = {}

        if self.cpu_samples:
            result.update(format_statistics_for_csv(self.cpu_samples, "cpu_percent"))

        if self.memory_samples:
            result.update(format_statistics_for_csv(self.memory_samples, "memory_usage_mb"))

        return result

    def finish(self) -> Dict[str, Any]:
        """完成实验，返回最终统计"""
        end_time = time.time()

        return {
            "total_results": len(self.results),
            "elapsed_seconds": round(end_time - self.start_time, 2),
            "start_time": self.metadata["start_time_human"],
            "end_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            **self.get_performance_stats(),
        }

    def save_results_to_csv(self, output_path: str, fieldnames: List[str]):
        """保存结果到CSV"""
        import csv

        enhanced_fieldnames = create_enhanced_csv_writer(fieldnames, self.metadata)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=enhanced_fieldnames, extrasaction='ignore')
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)

        print(f"[TRACKER] Saved {len(self.results)} results to {output_path}")


def demo_statistics():
    """演示统计功能"""
    print("=" * 60)
    print("Statistics Demo")
    print("=" * 60)

    # 示例数据
    values: List[float] = [100.0, 102.0, 98.0, 101.0, 99.0, 103.0, 97.0, 100.0, 101.0, 99.0]

    s = calculate_statistics(values)
    print(f"\nValues: {values}")
    print(f"Statistics:")
    for key, value in s.items():
        print(f"  {key}: {value:.4f}" if isinstance(value, float) else f"  {key}: {value}")

    # 成功率
    print(f"\nSuccess Rate:")
    rate_stats = calculate_rate(95, 100)
    for key, value in rate_stats.items():
        print(f"  {key}: {value:.4f}")

    # Observed rate (exact boundaries)
    print(f"\nObserved Rate (all success, n=60):")
    obs = calculate_observed_rate(60, 60)
    for key, value in obs.items():
        print(f"  {key}: {value}" if not isinstance(value, float) else f"  {key}: {value:.6f}")

    # 安全指标
    print(f"\nSecurity Metrics:")
    security_stats = calculate_security_metrics(
        false_accept_count=2,
        false_reject_count=3,
        total_legitimate=100,
        total_attack=50,
    )
    for key, value in security_stats.items():
        print(f"  {key}: {value:.4f}")

    # 元数据
    print(f"\nExperiment Metadata:")
    metadata = collect_experiment_metadata()
    for key, value in metadata.items():
        print(f"  {key}: {value}")


if __name__ == "__main__":
    demo_statistics()
