# 跨主机实验指南 (CROSS_HOST_EXPERIMENT)

## 概述

`run_cross_host_validation.py` 在两台独立主机之间运行 GMCP-R 协议对比实验，
测量真实广域网/局域网环境下的 RTT、吞吐量和成功率。

**矩阵**: 4 protocols × 2 msg_counts × 2 payloads × 20 repeats = **320 rows**

## 协议

| 协议 | 说明 |
|------|------|
| `gmcp_r` | GMCP-R 完整协议（Memory + HMAC + Checkpoint） |
| `seq_mac` | Sequential MAC（仅 HMAC(seq‖payload)） |
| `hash_chain` | Hash Chain（无认证标签） |
| `authenticated_hash_chain` | Hash Chain + HMAC 认证 |

## 环境要求

- 两台主机之间有网络连通性（同一局域网或公网）
- Python 3.10+，安装 gmcp 包
- 确保防火墙放行指定端口（默认 9001）

## 快速开始

### 方式一：单机自测

```bash
# 自动启动内嵌服务器并在本地运行实验
python run_cross_host_validation.py --port 9001
```

### 方式二：两台主机（推荐）

**机器 A（服务端）**:
```bash
python run_cross_host_validation.py --bind-host 0.0.0.0 --port 9001
```

**机器 B（客户端）**:
```bash
python run_cross_host_validation.py --host <机器A的IP> --port 9001 --no-spawn-server
```

### 方式三：快速验证

```bash
# 仅运行 1 轮重复（4×2×2×1 = 16 rows）
python run_cross_host_validation.py --host <server-ip> --port 9001 --no-spawn-server --quick
```

## 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `127.0.0.1` | 服务器地址（客户端模式必填） |
| `--port` | `9001` | 服务器端口 |
| `--bind-host` | `127.0.0.1` | 服务器绑定地址（`0.0.0.0` 监听所有接口） |
| `--no-spawn-server` | `False` | 不启动内嵌服务器，连接到外部服务器 |
| `--quick` | `False` | 快速模式（1 轮重复） |
| `--repeats` | `20` | 覆盖默认重复次数 |

## 安全机制

- **拒绝伪造数据**: 如果无法连接到真实服务器，脚本会立即退出，不会生成伪造 CSV
- **运行前连接检查**: 在开始实验矩阵之前，先 PING 服务器确认可达
- **逐行写入**: 每完成一个实验立即写入 CSV 并 flush，中断后已有数据不丢失

## 输出

结果写入 `results/cross_host/cross_host_results.csv`，主要列：

| 列名 | 说明 |
|------|------|
| `protocol` | 协议名称 |
| `client_host_id` | 客户端主机标识 |
| `server_host_id` | 服务器主机标识 |
| `network_path_type` | `loopback` / `lan` / `wan` |
| `baseline_ping_rtt_ms` | 基线 TCP RTT（中位数，毫秒） |
| `message_count` | 消息数量 |
| `payload_size` | 负载大小（字节） |
| `repeat_id` | 重复编号 (1-20) |
| `success_rate` | 成功率 (%) |
| `throughput_msg_per_sec` | 吞吐量（消息/秒） |
| `avg_rtt_ms` / `p50_rtt_ms` / `p95_rtt_ms` / `p99_rtt_ms` | RTT 统计 |

## 验证

```bash
python validate_cross_host_artifact.py
```

## 网络路径分类

脚本根据目标 IP 自动分类：

- `loopback`: 127.0.0.1 / localhost
- `lan`: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- `wan`: 其他公网地址

分类结果记录在 CSV 的 `network_path_type` 列中。

## 注意事项

1. macOS 上 `tc` 命令不可用，跨主机实验使用纯 TCP 测量（不依赖 tc/netem）
2. 如果需要在 Linux 上结合 tc/netem 进行弱网实验，请使用 `run_netem_validation.py`
3. 服务器端的嵌入式服务器支持多客户端并发连接
