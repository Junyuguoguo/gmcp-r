# GMCP-R 投稿前实验修订设计

日期：2026-07-10

状态：已完成交互确认，等待实施计划

范围：实验代码、重新生成的 CSV、汇总 CSV、图表和运行清单

不在范围内：论文 Markdown、DOCX、PDF、生产部署和协议改为数字签名

## 1. 背景与目标

当前 GMCP-R 原型与实验存在七类投稿风险：

1. MemoryTicket 的服务器专用 HMAC 密钥模型与客户端验证代码矛盾，且恢复响应没有整体认证。
2. DATA 算法、HMAC 输入和实现验证项不完全一致，Checkpoint 存在两套密钥实现。
3. 现有 900 条恢复记录全部是 `ticket_seq=100`、`server_seq=100`，没有证明旧票据向更靠前服务器状态重新同步。
4. 普通 Hash Chain 没有消息认证，且 Seq+MAC 被注入其语义之外的 `prev_mem`，导致 baseline 不公平。
5. 现有 Checkpoint 实验固定重放 49 条，不能直接展示 GMCP-R 的 O(k) 与 Hash Chain 的 O(n) 恢复差异。
6. 单个全局状态锁串行化所有 session，并发置信区间的统计单位错误。
7. 实验中的 100% 是有限样本观测，不是密码学安全证明。

本次修订的目标是让协议代码、攻击模型、实验矩阵、统计口径和结果产物形成一条可审计证据链。所有安全结论必须能够从原始 CSV 重算，所有性能图必须能够追溯到同一批原始记录。

## 2. 已确认的设计决策

### 2.1 恢复认证模型

保留 HMAC MemoryTicket：

- `K_T` 仅服务器持有，用于构造和验证 MemoryTicket。
- 客户端把 MemoryTicket 当作不透明凭证，只保存并原样提交。
- 客户端不得导入 `TICKET_AUTH_KEY`，也不得调用票据 HMAC 验证函数。
- 恢复请求继续使用客户端与服务器共享的 `K_D` 认证。
- 整个 `RECOVERY_RESPONSE` 使用 `K_D` 认证，使客户端能够验证服务器返回的恢复状态。

本次不改用 Ed25519，也不把 TLS/QUIC 作为本地实验正确性的隐含前提。

### 2.2 实现策略

采用“统一实验核心”路线：保留主要命令入口和已有目录习惯，同时统一协议编码、恢复认证、Checkpoint、baseline、锁管理和统计逻辑。避免在多个实验脚本中复制安全关键代码。

### 2.3 产物隔离

新实验默认写入：

```text
results/submission_revision/
  manifest.json
  protocol_contracts/
  baseline/
  recovery/
  checkpoint_cost/
  concurrency/
```

每个实验目录包含原始 CSV、汇总 CSV 和 `figures/`。实施和试跑阶段不覆盖当前 `results/` 与 `paper_data/` 中的已有数据。

## 3. 协议代码设计

### 3.1 规范编码与认证输入

所有字典型认证对象使用现有确定性 JSON 规则：

- UTF-8；
- `ensure_ascii=False`；
- `sort_keys=True`；
- 分隔符为 `(',', ':')`；
- 认证时仅移除当前对象的认证标签字段；
- 不允许 NaN、Infinity 等非标准 JSON 数值进入认证对象。

统一接口负责：

- 规范编码；
- 添加 HMAC；
- 验证 HMAC；
- 必需字段检查；
- 拒绝未知或不允许的安全关键字段。

DATA 的 HMAC 覆盖除 `auth_tag` 外的完整报文字典，包括 `type`、`protocol`、`session_id`、`sender_id`、`epoch`、`seq`、`prev_mem`、`payload`、`payload_hash`、`timestamp` 和实验中加入的 `checkpoint_interval`。

### 3.2 DATA 验证顺序

服务端 DATA 验证器按以下顺序执行，并保证所有拒绝路径不修改状态：

1. 验证必需字段和类型。
2. 验证 `type == DATA` 和 `protocol == gmcp_r`。
3. 验证完整报文 HMAC。
4. 验证 `session_id`、`sender_id` 和 `epoch` 与 session 上下文一致。
5. 验证 `seq` 为整数且满足单调、连续关系。
6. 重新计算 `payload_hash`。
7. 验证 `prev_mem == last_mem`。
8. 计算新 memory，并原子更新 `last_seq` 与 `last_mem`。

测试必须证明 `sender_id="different-sender"` 即使带有合法 HMAC 也会被拒绝。

### 3.3 MemoryTicket 服务端边界

MemoryTicket 仍可在网络上表示为结构化 JSON，但客户端代码把它作为不可解释对象处理：

- 客户端不访问票据内部的 `server_auth_tag`；
- 客户端不根据票据内部字段决定是否更新恢复状态；
- 票据字段、过期时间、Checkpoint 和 nonce 只由服务器验证；
- 实验需要的 `ticket_seq` 等审计值由已认证的响应顶层审计字段或服务器结果记录提供，不能通过客户端调用 `K_T` 验证得到。

无效票据实验需要的过期、错误会话和结构性回滚票据由服务器侧测试夹具生成。网络客户端只接收夹具输出，不加载服务器专用密钥。

### 3.4 恢复请求和恢复响应

恢复请求新增随机 `recovery_nonce`。该 nonce 与请求全部其他字段一起由请求 `auth_tag` 覆盖。

所有成功和失败的 `RECOVERY_RESPONSE` 都包含：

- `type`；
- `ok`；
- `reason`；
- `session_id`；
- `epoch`；
- 原请求的 `recovery_nonce`；
- `server_time`；
- `recovery_auth_tag`。

成功响应另外包含：

- `server_last_seq`；
- `server_last_mem`；
- `checkpoint_seq`；
- `checkpoint_mem`；
- 替换 MemoryTicket；
- 恢复模式和服务器审计字段。

`recovery_auth_tag = HMAC(K_D, canonical_json(response_without_recovery_auth_tag))`。

客户端按以下顺序处理响应：

1. 验证响应类型和必需字段。
2. 验证 `recovery_auth_tag`。
3. 验证 `session_id`、`epoch` 和 `recovery_nonce` 与请求一致。
4. 若 `ok` 为假，只记录经过认证的拒绝原因。
5. 若 `ok` 为真，才接受顶层恢复状态并保存替换票据。

响应标签缺失、标签篡改、nonce 不匹配或旧响应重放都不得更新客户端状态。

### 3.5 Checkpoint 统一

Checkpoint 的唯一认证密钥为 `CHECKPOINT_AUTH_KEY`。`gmcp/checkpoint_manager.py` 作为权威实现，负责创建、验证、定位和持久化 Checkpoint。

旧 `gmcp/checkpoint.py` 不再独立使用 `DATA_AUTH_KEY`。为减少导入破坏，可将其改为调用权威实现的兼容层，并在模块注释中标记 deprecated；仓库内新代码不得直接实现第二套 Checkpoint HMAC。

### 3.6 锁和 nonce 原子性

服务端使用：

- 一个短临界区 registry lock，仅负责创建或获取 `SessionContext`；
- 每个 session 一个独立锁，保护该 session 的 state、verifier 和 CheckpointManager；
- 一个独立的 nonce store lock，原子执行“检查未使用并写入已使用集合”。

恢复流程先验证票据和 Checkpoint，最后才原子消费 nonce。票据过期、低于恢复下界、Checkpoint 不一致或响应构造失败均不得消费 nonce。

同一 nonce 的两个并发请求必须恰好一个成功。不同 session 的 DATA 处理不得因另一个 session 的长临界区而等待全局状态锁。

## 4. Baseline 公平性设计

### 4.1 主对比协议

主对比包含：

- GMCP-R；
- Authenticated Hash Chain；
- Seq+MAC；
- Ticket Only。

Authenticated Hash Chain 在原链式字段上增加完整报文 HMAC，使用与 GMCP-R 相同等级的消息认证能力，但没有 MemoryTicket 和 Checkpoint。普通无认证 Hash Chain 只作为负面对照，不进入公平性能排名。

### 4.2 攻击语义

攻击统一映射为安全属性：

- `drop`：序列缺口；
- `modify`：载荷完整性；
- `replay`：旧消息重放；
- `history_pointer`：GMCP-R 的 `prev_mem` 或 Authenticated Hash Chain 的 `prev_hash`；
- `none`：合法流量。

每行记录：

- `attack_property`；
- `attack_applicable`；
- `attack_injected`；
- `expected_capability`；
- `observed_detected`；
- `detection_reason`。

Seq+MAC 和 Ticket Only 对 `history_pointer` 记录为 `attack_applicable=False` 和 `N/A`，不纳入其检测率分母。汇总不再用一个跨不同语义攻击的总百分比替代能力说明，而是同时提供逐属性结果和能力矩阵。

### 4.3 自适应篡改负面对照

单独运行普通 Hash Chain 与 Authenticated Hash Chain 的自适应篡改实验：攻击者修改 payload，并重算普通 `payload_hash` 和 `chain_hash`，但不能生成认证 HMAC。

预期结果：

- 普通 Hash Chain 接受；
- Authenticated Hash Chain 拒绝；
- 该结果说明普通哈希链不抵抗掌握公开算法的主动篡改者。

## 5. 恢复实验设计

### 5.1 现有异常恢复控制实验

保留 drop、modify、replay、prev_mem 和 disconnect 五类异常恢复实验，继续作为“异常后能否进入经过认证的恢复流程”的控制数据。客户端改为验证完整恢复响应，不再验证替换票据 HMAC。

### 5.2 新增恢复窗口实验

新增五类场景：

1. `same_point_control`：票据 seq=100，服务器恢复前 seq=100，成功响应为 seq=100。
2. `ack_loss_forward_sync`：服务器已接受 101-149，客户端故意丢弃这些响应并保留 seq=100 票据；成功恢复返回 seq=149。
3. `old_ticket_within_window`：一个连接推进服务器到 seq=149，另一个持 seq=100 票据的客户端实例恢复；票据仍在当前窗口内，服务器返回 seq=149。
4. `ticket_below_floor`：服务器推进并创建新的 Checkpoint，使 seq=100 票据低于恢复下界；恢复被拒绝且服务器状态不变。
5. `concurrent_nonce_reuse`：两个连接通过 barrier 同时提交同一票据；恰好一个成功，另一个得到经过认证的 replay rejection。

非竞争场景矩阵：

- Checkpoint 间隔：50、100；
- payload：128、512 字节；
- 每配置 30 次；
- 4 个场景，共 480 行。

nonce 竞争场景：

- Checkpoint 间隔：50、100；
- 每配置 30 次；
- 共 60 行。

恢复窗口数据集共 540 行。主要审计列包括：

- `scenario`；
- `ticket_seq`；
- `client_last_seq_before_recovery`；
- `server_last_seq_before_recovery`；
- `checkpoint_floor_seq`；
- `response_server_seq`；
- `ticket_server_gap`；
- `response_advanced_by`；
- `request_auth_verified`；
- `response_auth_verified`；
- `response_nonce_match`；
- `server_ticket_verified`；
- `nonce_consumed`；
- `race_success_count`；
- `server_state_unchanged_on_reject`；
- `recovery_success`；
- `reason`。

## 6. O(k) 与 O(n) 恢复成本实验

### 6.1 矩阵

- 会话长度 `n`：1,000、10,000、100,000；
- Checkpoint 间隔 `k`：10、50、100、500；
- 恢复偏移：1、`floor(k/2)`、`k-1`；
- 协议：GMCP-R、Authenticated Hash Chain；
- 每配置 30 次。

每个 `(n, k, repeat_id)` 生成一次确定性消息历史，两个协议使用相同 payload 序列。目标序号定义为：

```text
checkpoint_base = n - k
target_seq = checkpoint_base + recovery_offset
```

GMCP-R 从 `checkpoint_base` 的认证 Checkpoint 开始验证后缀；Authenticated Hash Chain 从会话起点验证到 `target_seq`。

共生成 `3 * 4 * 3 * 2 * 30 = 2160` 条恢复测量记录。

### 6.2 测量指标

- `recovery_latency_ns`，使用 `time.perf_counter_ns()`；
- `replay_count`；
- `recovery_material_bytes`；
- `logical_disk_read_bytes`；
- `checkpoint_bytes`；
- `target_seq`；
- `reconstructed_state` 与 `target_state`；
- `reconstruction_match`；
- `auth_records_verified`；
- `warmup` 与正式测量标记。

`logical_disk_read_bytes` 表示应用实际读取并解析的持久化字节数，不宣称为物理设备读取量。实验不尝试清除操作系统页缓存；此限制写入 manifest。

临时日志按配置生成，完成测量和 CSV 落盘后删除。试跑先使用 3 次重复，验证矩阵和资源开销后再运行完整 30 次。

## 7. 并发实验设计

并发实验直接对比：

- `global_lock` 兼容模式；
- `per_session_lock` 修订模式。

矩阵：

- 客户端数：1、2、5、10、20；
- 每客户端消息数和 payload 固定为同一配置；
- 每配置 30 次独立运行；
- 每次运行使用全新 session 集合。

原始行记录运行级指标。汇总 RTT 的 95% CI 必须由 30 个独立运行的 `rtt_mean_ms` 计算，不能平均每轮内部消息级 CI。锁策略、客户端数和 repeat 是统计分组键。

并发结果仍只支持给定客户端范围内的功能与性能观察，不扩展为大规模可扩展性结论。

## 8. 统计设计

### 8.1 连续指标

连续指标报告：

- 样本数；
- 均值；
- 样本标准差；
- 中位数；
- P95；
- 基于独立运行均值的 Student t 95% CI。

统计模块不得在运行环境缺少 SciPy 时静默失败。实施时移除未声明的强制 SciPy 导入，使用 NumPy/标准库和受测试的 t 临界值实现计划中的 95% CI。

### 8.2 比例指标

比例结果必须报告分子和分母。对全成功或全失败观测，输出双侧 95% Clopper-Pearson 精确边界；其他比例至少输出 Wilson 区间，并在列名中注明方法。

全成功时，下界公式为：

```text
lower = (alpha / 2) ** (1 / n), alpha = 0.05
```

因此测试固定校验：

- 60/60：下界约 94.04%；
- 180/180：下界约 97.97%；
- 900/900：下界约 99.59%。

图表和 CSV 使用“observed success/detection rate”命名，不使用“proved secure”等证明性措辞。

## 9. 错误处理与状态不变量

必须通过测试维持以下不变量：

- DATA 拒绝不修改 `last_seq` 或 `last_mem`；
- 恢复拒绝不修改服务器权威历史；
- 响应认证失败不修改客户端状态；
- 所有票据和 Checkpoint 验证通过前不消费 nonce；
- nonce 消费成功后同一 nonce 永不在当前进程内再次成功；
- Checkpoint 必须满足 `checkpoint_seq <= ticket_seq <= server_seq`；
- 窗口内旧票据只用于认证恢复资格，不使服务器回滚；
- 客户端只有在响应 HMAC、请求 nonce 和上下文全部匹配时才前向同步。

## 10. 测试策略

### 10.1 测试先行

实现前先增加会失败的测试，至少覆盖：

- DATA `sender_id` 不匹配；
- DATA `protocol` 不匹配；
- 缺失必需字段；
- 恢复响应字段篡改；
- 恢复响应标签缺失；
- 恢复响应 nonce 重放；
- 客户端路径不导入 `TICKET_AUTH_KEY`；
- Checkpoint 只使用 `CHECKPOINT_AUTH_KEY`；
- 普通 Hash Chain 自适应篡改被接受的负面对照；
- Authenticated Hash Chain 对同一篡改拒绝；
- 旧票据 100 到服务器 149 的前向同步；
- 低于恢复下界的票据拒绝且状态不变；
- 两线程同 nonce 恰好一个成功；
- 两个不同 session 能进入各自临界区；
- 运行级 CI 对现有 5 客户端数据得到约 0.0896 ms 半宽；
- 60/60、180/180、900/900 精确区间下界。

### 10.2 产物契约

验证器检查：

- 每个 CSV 的必需列；
- 每个矩阵组合的行数；
- 无重复主键；
- 汇总值可从原始 CSV 重算；
- O(k)/O(n) 数据覆盖全部 2160 行；
- 所有 `reconstruction_match` 与预期一致；
- 图表读取的输入文件哈希记录在 manifest；
- 图表不存在空组、N/A 被误计入分母或布尔列被字符串错误聚合。

## 11. 图表设计

最终至少生成：

1. Baseline 逐安全属性检测结果与能力矩阵。
2. 普通 Hash Chain 与 Authenticated Hash Chain 自适应篡改对照。
3. 恢复窗口场景的接受/拒绝和前向同步序号差。
4. nonce 并发竞争结果。
5. GMCP-R 与 Authenticated Hash Chain 的恢复时间随 n 变化曲线，按 k 分面。
6. 重放条数随恢复偏移和 k 的变化。
7. 恢复材料字节数与逻辑磁盘读取字节数比较。
8. 全局锁与 per-session 锁的吞吐量、RTT 和运行级 95% CI。
9. 成功率/检测率的观测值与二项置信下界。

所有图表标题、坐标和图例明确区分观测结果、能力缺失 N/A 和实验环境。

## 12. 运行清单与可复现性

`manifest.json` 至少记录：

- 协议版本标识；
- Git commit 与工作区是否 dirty；
- Python、操作系统和依赖版本；
- 完整命令行；
- 随机种子；
- 开始/结束时间；
- 主机和端口；
- 本地回环或远程环境标识；
- 锁策略；
- 每个原始 CSV 的 SHA-256；
- 图表输入 CSV 的 SHA-256；
- 页缓存未清理等实验限制。

本地测试和完整本地实验是必需交付。远程服务器复现仅在用户已轮换截图中暴露的凭据并明确允许部署后进行；远程数据不得与本地回环数据混合汇总。

## 13. 实施阶段

1. 增加失败测试，固定当前缺陷。
2. 实现规范认证、恢复响应认证和 DATA 上下文检查。
3. 统一 Checkpoint 与 session/nonce 锁。
4. 实现 Authenticated Hash Chain 和公平攻击适配层。
5. 实现恢复窗口与 nonce 并发实验。
6. 实现 O(k)/O(n) 持久化恢复成本实验。
7. 修正并发统计与比例置信区间。
8. 运行快速矩阵和产物验证器。
9. 运行完整 30 次矩阵。
10. 生成汇总 CSV、图表和 manifest，并执行最终一致性检查。

## 14. 完成标准

只有同时满足以下条件才视为完成：

- 所有新增和现有相关测试通过；
- 客户端恢复代码不再验证 MemoryTicket HMAC；
- 恢复响应篡改和重放测试被拒绝；
- DATA `sender_id` 与 `protocol` 被验证；
- Checkpoint 只存在一个权威密钥实现；
- 主 baseline 使用 Authenticated Hash Chain；
- Seq+MAC 的历史指针攻击为 N/A；
- 恢复窗口 CSV 明确出现 `ticket_seq < server_seq` 的成功记录；
- 低于恢复下界的票据全部拒绝；
- nonce 竞争每次恰好一个成功；
- O(k)/O(n) 数据覆盖完整矩阵并重建一致；
- 并发 CI 使用 30 次运行级均值；
- 100% 结果同时报告分子、分母和置信下界；
- `results/submission_revision/` 中的 CSV、图表和 manifest 通过产物契约检查。
