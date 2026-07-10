# 表2：MemoryTicket无效票据拒绝结果

| 票据类型 | 恢复成功率 | 服务器拒绝原因 |
|----------|-----------|---------------|
| expired_ticket | 0% (被拒绝) | ticket expired |
| replayed_ticket | 0% (被拒绝) | ticket replay detected |
| tampered_ticket | 0% (被拒绝) | invalid ticket auth tag |
| rollback_ticket | 0% (被拒绝) | checkpoint_seq exceeds last_seq |
| wrong_session_ticket | 0% (被拒绝) | session_id mismatch |

**数据来源**：`results/real_ticket_recovery/real_ticket_recovery_results.csv`

**说明**：
- 恢复成功率：recovery_success=True的比例
- 服务器拒绝原因：server_reject_reason字段
- 所有票据类型均被服务端正确拒绝，符合预期
