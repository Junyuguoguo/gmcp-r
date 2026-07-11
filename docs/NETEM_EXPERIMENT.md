# tc/netem 弱网实验指南 (NETEM_EXPERIMENT)

## 概述

`run_netem_validation.py` 使用 Linux `tc/netem` 工具模拟 6 种代表性网络条件，
在本地回环接口上运行 GMCP-R 协议对比实验。

**矩阵**: 3 protocols × 6 conditions × 10 repeats = **180 rows**

## 环境要求

- **Linux 操作系统**（tc/netem 仅支持 Linux）
- `iproute2` 包（提供 `tc` 命令）
- **sudo 权限**（密码或 NOPASSWD）
- Python 3.10+，安装 gmcp 包

## 6 种网络条件

| 条件 | 说明 | 丢包 | 延迟 | 抖动 | 乱序 |
|------|------|------|------|------|------|
| `control` | 无损伤（基线） | 0% | 0ms | 0ms | 0% |
| `mild` | 轻度损伤（良好 WiFi） | 1% | 30ms | 10ms | 0% |
| `mobile` | 移动 4G | 2% | 60ms | 30ms | 5% |
| `poor` | 差网络 | 5% | 100ms | 50ms | 5% |
| `severe` | 严重劣化（卫星链路） | 10% | 200ms | 80ms | 10% |
| `loss_heavy` | 高丢包（拥塞网络） | 20% | 50ms | 20ms | 5% |

## 快速开始

```bash
# 完整实验（需要 sudo）
sudo python run_netem_validation.py --interface lo

# 快速验证（1 轮重复 → 18 rows）
sudo python run_netem_validation.py --interface lo --quick

# 仅运行部分条件
sudo python run_netem_validation.py --interface lo --conditions control,mobile,severe

# 自定义重复次数
sudo python run_netem_validation.py --interface lo --repeats 5
```

## 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--interface`, `-i` | `lo` (Linux) | 应用 tc/netem 规则的网络接口 |
| `--port` | `9002` | 内嵌服务器端口 |
| `--quick` | `False` | 快速模式（1 轮重复） |
| `--repeats` | `10` | 覆盖默认重复次数 |
| `--conditions` | 全部 | 逗号分隔的条件名称 |

## 安全机制

### 拒绝运行条件

脚本在以下情况**拒绝生成数据**：

1. **非 Linux 系统**: tc/netem 仅支持 Linux 内核
2. **无 sudo 权限**: tc 命令需要 root 权限
3. **tc 命令不存在**: 需要安装 iproute2

### 自动清理

- 使用 Python context manager 确保每组实验后清理 tc 规则
- 脚本退出时自动调用 `clear_tc_netem()`
- Shell 脚本使用 `trap cleanup EXIT` 确保清理

## 协程 Shell 脚本

### apply_netem.sh

```bash
# 应用特定条件
sudo ./scripts/apply_netem.sh mobile lo

# 应用后保持（Ctrl+C 清理）
sudo ./scripts/apply_netem.sh severe eth0
```

### clear_netem.sh

```bash
# 清除所有规则
sudo ./scripts/clear_netem.sh lo
```

## 输出

结果写入 `results/netem_validation/netem_validation_results.csv`，主要列：

| 列名 | 说明 |
|------|------|
| `protocol` | 协议名称 |
| `condition_name` | 网络条件名称 |
| `loss_rate_pct` | 丢包率 (%) |
| `delay_ms` | 延迟 (ms) |
| `jitter_ms` | 抖动 (ms) |
| `reorder_pct` | 乱序率 (%) |
| `success_rate` | 成功率 (%) |
| `throughput_msg_per_sec` | 吞吐量（消息/秒） |
| `avg_rtt_ms` / `p50_rtt_ms` / `p95_rtt_ms` / `p99_rtt_ms` | RTT 统计 |

## 验证

```bash
python validate_netem_artifact.py
```

## 故障排除

### "tc/netem is a Linux-only feature"

macOS 和 Windows 不支持 tc/netem。请在 Linux 虚拟机或远程 Linux 主机上运行。

### "requires passwordless sudo"

```bash
# 方法 1: 以 root 运行
sudo python run_netem_validation.py --interface lo

# 方法 2: 配置 NOPASSWD
sudo visudo
# 添加: yourusername ALL=(ALL) NOPASSWD: /sbin/tc
```

### tc 规则未清理

```bash
# 手动清理
sudo ./scripts/clear_netem.sh lo
# 或
sudo tc qdisc del dev lo root
```

## 注意事项

1. 在回环接口 (`lo`) 上应用 tc/netem 只影响本机进程间的通信
2. 实验期间不要在其他终端修改 tc 规则
3. 使用 `--conditions` 选择性运行可以缩短实验时间
4. 每个条件结束后 tc 规则会自动清理，不会影响下一个条件
