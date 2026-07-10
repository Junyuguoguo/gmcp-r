# -*- coding: utf-8 -*-
# monitor_resources.py
#
# 资源消耗监控模块
# 使用 psutil 采集 CPU、内存、网络带宽等指标
# 支持后台线程持续采样，供基准测试脚本集成

import os
import sys
import time
import threading
from typing import Dict, Any, List, Optional

import psutil


class ResourceMonitor:
    """
    后台资源监控器

    用法：
        monitor = ResourceMonitor(interval=0.5)
        monitor.start()
        # ... 执行测试 ...
        monitor.stop()
        stats = monitor.get_stats()
    """

    def __init__(self, interval: float = 0.5, pid: Optional[int] = None):
        """
        参数:
            interval: 采样间隔（秒）
            pid: 监控的目标进程 PID，默认为当前进程
        """
        self.interval = interval
        self.pid = pid or os.getpid()
        self._process: Optional[psutil.Process] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # 采样数据
        self.timestamps: List[float] = []
        self.cpu_percent: List[float] = []       # 进程 CPU 占用 (%)
        self.system_cpu_percent: List[float] = []  # 系统总 CPU 占用 (%)
        self.rss_mb: List[float] = []            # 驻留内存 (MB)
        self.vms_mb: List[float] = []            # 虚拟内存 (MB)
        self.num_threads: List[int] = []         # 线程数
        self.bytes_sent: List[int] = []          # 累计发送字节
        self.bytes_recv: List[int] = []          # 累计接收字节

        # 网络基线（start 时记录）
        self._net_baseline_sent: int = 0
        self._net_baseline_recv: int = 0

    def _init_process(self):
        try:
            self._process = psutil.Process(self.pid)
            # 预热一次，避免首次采样偏差
            self._process.cpu_percent()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[ResourceMonitor] Warning: cannot access process {self.pid}: {e}")
            self._process = None

    def _read_net_counters(self) -> tuple:
        """读取系统网络计数器（bytes_sent, bytes_recv）"""
        try:
            counters = psutil.net_io_counters()
            return counters.bytes_sent, counters.bytes_recv
        except Exception:
            return 0, 0

    def _sample_once(self):
        """执行一次采样"""
        now = time.time()
        self.timestamps.append(now)

        # 系统 CPU
        self.system_cpu_percent.append(psutil.cpu_percent(interval=None))

        # 进程级指标
        if self._process is not None:
            try:
                self.cpu_percent.append(self._process.cpu_percent(interval=None))
                mem = self._process.memory_info()
                self.rss_mb.append(mem.rss / (1024 * 1024))
                self.vms_mb.append(mem.vms / (1024 * 1024))
                self.num_threads.append(self._process.num_threads())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.cpu_percent.append(0.0)
                self.rss_mb.append(0.0)
                self.vms_mb.append(0.0)
                self.num_threads.append(0)
        else:
            self.cpu_percent.append(0.0)
            self.rss_mb.append(0.0)
            self.vms_mb.append(0.0)
            self.num_threads.append(0)

        # 网络计数
        sent, recv = self._read_net_counters()
        self.bytes_sent.append(sent - self._net_baseline_sent)
        self.bytes_recv.append(recv - self._net_baseline_recv)

    def _run_loop(self):
        while self._running:
            self._sample_once()
            time.sleep(self.interval)

    def start(self):
        """启动后台监控线程"""
        if self._running:
            return
        self._init_process()
        # 记录网络基线
        sent, recv = self._read_net_counters()
        self._net_baseline_sent = sent
        self._net_baseline_recv = recv

        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print(f"[ResourceMonitor] Started (pid={self.pid}, interval={self.interval}s)")

    def stop(self):
        """停止监控"""
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=self.interval * 3)
            self._thread = None
        # 最终采样
        self._sample_once()
        print(f"[ResourceMonitor] Stopped ({len(self.timestamps)} samples)")

    def get_stats(self) -> Dict[str, Any]:
        """
        汇总统计信息

        返回字典包含各项指标的 min / max / mean / std / p50 / p95 / p99
        """
        import numpy as np

        def _summary(values: list, prefix: str) -> Dict[str, float]:
            if not values:
                return {}
            arr = np.array(values, dtype=float)
            return {
                f"{prefix}_min": round(float(np.min(arr)), 4),
                f"{prefix}_max": round(float(np.max(arr)), 4),
                f"{prefix}_mean": round(float(np.mean(arr)), 4),
                f"{prefix}_std": round(float(np.std(arr, ddof=1)), 4) if len(arr) > 1 else 0.0,
                f"{prefix}_p50": round(float(np.percentile(arr, 50)), 4),
                f"{prefix}_p95": round(float(np.percentile(arr, 95)), 4),
                f"{prefix}_p99": round(float(np.percentile(arr, 99)), 4),
            }

        stats: Dict[str, Any] = {}
        stats["sample_count"] = len(self.timestamps)

        if self.timestamps:
            duration = self.timestamps[-1] - self.timestamps[0]
            stats["duration_seconds"] = round(duration, 4)

        stats.update(_summary(self.cpu_percent, "proc_cpu_pct"))
        stats.update(_summary(self.system_cpu_percent, "sys_cpu_pct"))
        stats.update(_summary(self.rss_mb, "rss_mb"))
        stats.update(_summary(self.vms_mb, "vms_mb"))
        stats.update(_summary(self.num_threads, "threads"))

        # 网络流量（取最终值 = 累计增量）
        if self.bytes_sent:
            stats["total_bytes_sent"] = self.bytes_sent[-1]
            stats["total_mb_sent"] = round(self.bytes_sent[-1] / (1024 * 1024), 4)
        if self.bytes_recv:
            stats["total_bytes_recv"] = self.bytes_recv[-1]
            stats["total_mb_recv"] = round(self.bytes_recv[-1] / (1024 * 1024), 4)

        return stats

    def get_timeseries(self) -> Dict[str, List]:
        """返回原始时间序列数据，供绘图使用"""
        t0 = self.timestamps[0] if self.timestamps else 0
        return {
            "elapsed_sec": [round(t - t0, 4) for t in self.timestamps],
            "cpu_percent": self.cpu_percent,
            "system_cpu_percent": self.system_cpu_percent,
            "rss_mb": self.rss_mb,
            "vms_mb": self.vms_mb,
            "num_threads": self.num_threads,
            "bytes_sent_cumulative": self.bytes_sent,
            "bytes_recv_cumulative": self.bytes_recv,
        }


# ──────────────────────────────────────────────
# 独立运行：快速验证 / 持续监控
# ──────────────────────────────────────────────
def main():
    """
    独立运行时，持续监控当前进程并每 5 秒输出摘要
    Ctrl+C 退出后打印最终统计
    """
    import argparse

    parser = argparse.ArgumentParser(description="实时资源监控")
    parser.add_argument("--interval", type=float, default=0.5, help="采样间隔（秒）")
    parser.add_argument("--pid", type=int, default=None, help="目标 PID（默认当前进程）")
    parser.add_argument("--duration", type=float, default=0, help="监控时长（秒），0=无限")
    parser.add_argument("--output", type=str, default=None, help="输出 JSON 文件路径")
    args = parser.parse_args()

    monitor = ResourceMonitor(interval=args.interval, pid=args.pid)
    monitor.start()

    try:
        start = time.time()
        while True:
            time.sleep(5)
            elapsed = time.time() - start
            n = len(monitor.timestamps)
            if n > 0:
                last_cpu = monitor.cpu_percent[-1]
                last_rss = monitor.rss_mb[-1]
                print(f"  [{elapsed:6.1f}s] samples={n:4d}  "
                      f"cpu={last_cpu:5.1f}%  rss={last_rss:7.1f}MB")
            if args.duration > 0 and elapsed >= args.duration:
                break
    except KeyboardInterrupt:
        print("\n[Interrupted]")

    monitor.stop()
    stats = monitor.get_stats()

    print("\n" + "=" * 60)
    print("Resource Monitor Summary")
    print("=" * 60)
    for k, v in stats.items():
        print(f"  {k}: {v}")

    if args.output:
        import json
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2, ensure_ascii=False)
        print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
