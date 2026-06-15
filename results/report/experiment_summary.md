# GMCP-R Experiment Summary

## 1. 实验概览
本项目实验体系分为 baseline 对比、真实 TCP 双端通信、滑动窗口优化、攻击后恢复、弱网/断续网络模拟、MemoryTicket 安全性六组。

## 2. baseline 对比结论
GMCP-R keeps secure memory recovery while reducing modeled recovery latency and extra bytes compared with hash-chain replay.
注意：baseline 是 protocol-level simulation，不是真实 TCP 网络实验。

## 3. 真实双端通信结论
真实 TCP 结果只来自 real_network 目录，需要 real_tcp_server.py 正在运行。

## 4. 有记忆通信验证结论
当前 summary 中正常通信 memory match rate 为 100.0%，prev_mem detection rate 为 100.0%。

## 5. 滑动窗口优化结论
window_size=1/5/10 的结果用于比较吞吐量、Application-level RTT 与 memory match 的权衡。

## 6. 攻击后恢复结论
real_recovery 结果验证攻击检测、RECOVERY_REQUEST/RECOVERY_RESPONSE、MemoryTicket 校验、同步恢复和最终记忆一致性。

## 7. 弱网实验结论
Controlled weak-network simulation separates loss, reordering, and delay. GMCP-R is expected to keep high memory match with lower recovery cost than hash_chain.
注意：weak_network 是 controlled weak-network simulation，不是真实 TCP 网络实验。

## 8. MemoryTicket 安全性结论
ticket_security 实验覆盖 valid、expired、replayed、tampered、wrong_session、rollback 六类 ticket 场景。

## 9. 当前不足
协议级模拟的时延与吞吐分数来自确定性模型，不能替代跨地域真实网络测量；真实实验仍依赖服务器部署稳定性和单客户端场景。

## 10. 后续改进方向
建议补充多客户端并发、真实 tc/netem 弱网、跨云地域重复实验、更多 payload 分布、以及更接近生产密钥轮换的 ticket 生命周期测试。
