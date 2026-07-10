# 论文数据清单

**生成时间**: 2026-07-04
**数据版本**: v5.0 (最终版)
**实验环境**: 本地TCP回环 (127.0.0.1)

## 数据文件

| 文件 | 实验 | 记录数 | 重复次数 | 说明 |
|------|------|--------|----------|------|
| 01_real_baseline.csv | Baseline对比 | 3,600 | 30次/配置 | Python TCP原型 |
| 02_ticket_attacks.csv | 票据攻击 | 300 | 30次/配置 | Python TCP原型 |
| 03_performance.csv | 性能基准 | 120 | 3次/配置 | 本地计算 |
| 04_concurrency.csv | 并发测试 | 15 | 3次/配置 | 1-20客户端 |
| 05_weak_network.csv | 弱网仿真 | 150 | 2次/配置 | 代码级仿真 |
| 06_memory_ticket_recovery.csv | MemoryTicket恢复 | 900 | 30次/配置 | Python TCP原型 |
| 07_checkpoint_recovery.csv | Checkpoint恢复 | 120 | 10次/配置 | Python TCP原型 |

**总数据量**: 5,205条

## 重复次数说明

- **MemoryTicket恢复和票据攻击实验**：每配置重复30次
- **Checkpoint恢复实验**：每配置重复10次
- **Baseline、MemoryTicket恢复和票据攻击实验**：每配置重复30次
- **性能与并发实验**：当前每配置重复3次

## 实验环境

- **客户端**: Python 3.11, macOS (M1 Pro)
- **服务器**: Python 3.11, 本地 (127.0.0.1:9000)
- **网络**: 本地TCP回环
- **密码学**: HMAC-SHA256, SHA-256

## 关键结果

### MemoryTicket恢复实验 (06)
- 恢复成功率: **100%** (900/900)
- 记忆一致率: **100%** (900/900)
- 票据验证率: **100%** (900/900)
- 审计字段: submitted_ticket_present, server_ticket_verified, response_state_match 均为100%

### Checkpoint恢复实验 (07)
- 恢复成功率: **100%** (120/120)
- 重建一致率: **100%** (120/120)
- reconstructed_mem == target_mem: **120/120**
- replay_count一致性: **120/120**

### 票据攻击实验 (02)
- 所有票据拒绝率: **100%** (300/300)
- 拒绝原因: ticket expired, ticket replay detected, invalid ticket auth tag, checkpoint_seq exceeds last_seq, session_id mismatch

## 审计字段说明

### MemoryTicket审计字段 (06)
- `submitted_ticket_present`: 是否提交了票据
- `submitted_ticket_seq`: 提交票据的seq
- `server_ticket_verified`: 服务端是否验证了旧票据
- `response_state_match`: 响应状态与票据是否一致

### Checkpoint审计字段 (07)
- `checkpoint_seq`: 恢复时的checkpoint seq
- `checkpoint_mem`: 恢复时的checkpoint mem
- `target_seq`: 恢复目标seq
- `target_mem`: 恢复目标mem
- `replay_count`: 重放消息数
- `reconstructed_mem`: 重建后的mem

## 注意事项

1. 当前数据包混合包含本地回环、VPC TCP 原型和代码级弱网仿真结果；各实验口径以对应 CSV、summary 和正文说明为准。
2. Baseline 对比当前采用 30 次重复、共 3,600 条记录；正文不再使用早期 360 条/3 次重复口径。
3. 弱网仿真为代码级仿真，不是 tc/netem、ns-3 或操作系统级真实弱网评估。

## 使用方式

```python
import csv

with open('paper_data/06_memory_ticket_recovery.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row['attack_type'], row['recovery_success'], row['submitted_ticket_present'])
```
