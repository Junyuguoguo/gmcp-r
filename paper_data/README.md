# 论文数据清单

**数据版本**: v5.0
**生成环境**: Python 3.11, localhost TCP loopback (127.0.0.1)
**密码学**: HMAC-SHA256, SHA-256

## 数据文件

| # | 文件 | 实验 | 行数 | 重复次数 | 说明 |
|---|------|------|-----:|----------|------|
| 01 | `01_real_baseline.csv` | Baseline对比 | 7,200 | 30/config | GMCP-R vs 4基线, 5协议 × 8攻击条件 |
| 02 | `02_ticket_attacks.csv` | 票据攻击 | 300 | 30/config | 无效MemoryTicket拒绝测试 |
| 03 | `03_performance.csv` | 性能基准 | 1,200 | 30/config | 本地计算吞吐量基准 |
| 04 | `04_concurrency.csv` | 并发测试 | 150 | 30/config | 1–20并发客户端 |
| 05 | `05_weak_network.csv` | 弱网仿真 | 150 | 2/config | **代码级仿真**（非tc/netem/ns-3） |
| 06 | `06_memory_ticket_recovery.csv` | MemoryTicket恢复 | 900 | 30/config | 攻击/断连恢复 |
| 07 | `07_checkpoint_recovery.csv` | Checkpoint恢复 | 120 | 10/config | Checkpoint重建审计 |
| 08 | `08_recovery_window.csv` | 恢复窗口 | 760 | 30/config | Recovery window + ACK loss + nonce race |
| 09 | `09_checkpoint_cost.csv` | Checkpoint开销 | 2,160 | 30/config | O(k) vs O(n) 恢复代价 |

**总计**: 12,940 行

## 弱网仿真说明

`05_weak_network.csv` 为代码级仿真，在应用层模拟丢包和延迟。不是 Linux `tc/netem`、ns-3 或操作系统级真实弱网实验。仅作为恢复行为的补充证据。

## 关键结果

### MemoryTicket恢复 (06)
- 恢复成功率: **100%** (900/900)
- 记忆一致率: **100%** (900/900)

### Checkpoint恢复 (07)
- 恢复成功率: **100%** (120/120)
- 重建一致率: **100%** (120/120)

### 票据攻击 (02)
- 所有无效票据拒绝率: **100%** (300/300)

### 恢复窗口 (08)
- 非race场景: 720行, race场景: 40行
- 所有request/response auth和nonce binding均通过
