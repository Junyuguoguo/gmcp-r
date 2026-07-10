# -*- coding: utf-8 -*-
# gmcp/checkpoint_manager.py
#
# Checkpoint管理器：定期保存checkpoint，支持基于checkpoint的恢复

import time
import json
import os
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict

from gmcp.config import CHECKPOINT_AUTH_KEY, CHECKPOINT_INTERVAL
from gmcp.crypto_utils import hmac_sha256_hex, verify_hmac, canonical_json


@dataclass
class Checkpoint:
    """Checkpoint数据结构"""
    session_id: str
    epoch: int
    seq: int
    memory: str
    timestamp: float
    signature: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Checkpoint':
        return cls(**data)


def sign_checkpoint_fields(
    session_id: str,
    epoch: int,
    seq: int,
    memory: str,
    timestamp: Optional[float] = None,
) -> Dict[str, Any]:
    """Build a signed checkpoint dict using CHECKPOINT_AUTH_KEY."""
    fields: Dict[str, Any] = {
        "session_id": session_id,
        "epoch": epoch,
        "seq": seq,
        "memory": memory,
        "timestamp": timestamp if timestamp is not None else time.time(),
    }
    fields["signature"] = hmac_sha256_hex(CHECKPOINT_AUTH_KEY, fields)
    return fields


def verify_checkpoint_fields(fields: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a checkpoint dict signed with CHECKPOINT_AUTH_KEY."""
    signature = fields.get("signature")
    if not signature:
        return False, "missing signature"
    data = dict(fields)
    data.pop("signature", None)
    if not verify_hmac(CHECKPOINT_AUTH_KEY, data, signature):
        return False, "invalid checkpoint signature"
    return True, "ok"


class CheckpointManager:
    """
    Checkpoint管理器

    功能：
    1. 定期保存checkpoint（每CHECKPOINT_INTERVAL条消息）
    2. 支持基于checkpoint的恢复
    3. 支持checkpoint的持久化存储
    4. 记录checkpoint统计信息
    """

    def __init__(self, session_id: str, epoch: int, checkpoint_interval: int = CHECKPOINT_INTERVAL,
                 storage_dir: Optional[str] = None):
        self.session_id = session_id
        self.epoch = epoch
        self.checkpoint_interval = checkpoint_interval
        
        # 内存中的checkpoint列表
        self.checkpoints: List[Checkpoint] = []
        
        # 统计信息
        self.checkpoint_count = 0
        self.last_checkpoint_seq = 0
        self.replay_count = 0
        
        # 持久化存储路径
        self.storage_dir = storage_dir or f"checkpoints/{session_id}"
        os.makedirs(self.storage_dir, exist_ok=True)
    
    def should_checkpoint(self, seq: int) -> bool:
        """判断是否应该保存checkpoint"""
        return seq > 0 and seq % self.checkpoint_interval == 0
    
    def create_checkpoint(self, seq: int, memory: str) -> Checkpoint:
        """创建新的checkpoint"""
        checkpoint_data = {
            "session_id": self.session_id,
            "epoch": self.epoch,
            "seq": seq,
            "memory": memory,
            "timestamp": time.time(),
        }
        
        # 计算签名
        signature = hmac_sha256_hex(CHECKPOINT_AUTH_KEY, checkpoint_data)
        checkpoint_data["signature"] = signature
        
        checkpoint = Checkpoint(**checkpoint_data)
        
        # 保存到内存
        self.checkpoints.append(checkpoint)
        self.checkpoint_count += 1
        self.last_checkpoint_seq = seq
        
        # 持久化保存
        self._save_checkpoint_to_disk(checkpoint)
        
        print(f"[CHECKPOINT] Created checkpoint at seq={seq}, total={self.checkpoint_count}")
        
        return checkpoint
    
    def get_latest_checkpoint(self) -> Optional[Checkpoint]:
        """获取最新的checkpoint"""
        if not self.checkpoints:
            return None
        return self.checkpoints[-1]
    
    def get_checkpoint_for_seq(self, target_seq: int) -> Optional[Checkpoint]:
        """获取用于恢复到target_seq的最近checkpoint"""
        if not self.checkpoints:
            return None
        
        # 找到seq <= target_seq的最新checkpoint
        for checkpoint in reversed(self.checkpoints):
            if checkpoint.seq <= target_seq:
                return checkpoint
        
        return None
    
    def verify_checkpoint(self, checkpoint: Checkpoint) -> Tuple[bool, str]:
        """验证checkpoint的合法性"""
        # 验证签名
        data = checkpoint.to_dict()
        data.pop("signature", None)
        
        if not verify_hmac(CHECKPOINT_AUTH_KEY, data, checkpoint.signature):
            return False, "invalid checkpoint signature"
        
        # 验证session_id
        if checkpoint.session_id != self.session_id:
            return False, "session_id mismatch"
        
        # 验证epoch
        if checkpoint.epoch != self.epoch:
            return False, "epoch mismatch"
        
        return True, "ok"
    
    def prepare_recovery(self, target_seq: int) -> Tuple[Optional[Checkpoint], int]:
        """
        准备恢复：找到最近的checkpoint，计算需要重放的消息数
        
        返回：
        - checkpoint: 用于恢复的checkpoint（如果没有则为None）
        - replay_count: 需要重放的消息数
        """
        checkpoint = self.get_checkpoint_for_seq(target_seq)
        
        if checkpoint is None:
            # 没有checkpoint，需要从头开始
            return None, target_seq
        
        # 计算需要重放的消息数
        replay_count = target_seq - checkpoint.seq
        self.replay_count += replay_count
        
        print(f"[CHECKPOINT] Recovery from seq={checkpoint.seq} to {target_seq}, "
              f"replay_count={replay_count}")
        
        return checkpoint, replay_count
    
    def _save_checkpoint_to_disk(self, checkpoint: Checkpoint):
        """将checkpoint保存到磁盘"""
        filename = f"checkpoint_{checkpoint.seq:06d}.json"
        filepath = os.path.join(self.storage_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(checkpoint.to_dict(), f, indent=2)
    
    def load_checkpoints_from_disk(self):
        """从磁盘加载checkpoint"""
        if not os.path.exists(self.storage_dir):
            return
        
        for filename in sorted(os.listdir(self.storage_dir)):
            if filename.startswith("checkpoint_") and filename.endswith(".json"):
                filepath = os.path.join(self.storage_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    checkpoint = Checkpoint.from_dict(data)
                    
                    # 验证checkpoint
                    ok, reason = self.verify_checkpoint(checkpoint)
                    if ok:
                        self.checkpoints.append(checkpoint)
                        self.checkpoint_count += 1
                        self.last_checkpoint_seq = max(self.last_checkpoint_seq, checkpoint.seq)
                    else:
                        print(f"[CHECKPOINT] Invalid checkpoint {filename}: {reason}")
                except Exception as e:
                    print(f"[CHECKPOINT] Error loading {filename}: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取checkpoint统计信息"""
        return {
            "session_id": self.session_id,
            "epoch": self.epoch,
            "checkpoint_interval": self.checkpoint_interval,
            "checkpoint_count": self.checkpoint_count,
            "last_checkpoint_seq": self.last_checkpoint_seq,
            "replay_count": self.replay_count,
            "checkpoints_in_memory": len(self.checkpoints),
            "storage_dir": self.storage_dir,
        }
    
    def get_storage_size(self) -> int:
        """获取checkpoint存储大小（字节）"""
        total_size = 0
        if os.path.exists(self.storage_dir):
            for filename in os.listdir(self.storage_dir):
                filepath = os.path.join(self.storage_dir, filename)
                if os.path.isfile(filepath):
                    total_size += os.path.getsize(filepath)
        return total_size


class CheckpointRecoverySession:
    """
    基于Checkpoint的恢复会话
    
    用于在恢复过程中管理状态
    """
    
    def __init__(self, checkpoint_manager: CheckpointManager):
        self.checkpoint_manager = checkpoint_manager
        self.recovery_checkpoint: Optional[Checkpoint] = None
        self.target_seq: int = 0
        self.replay_count: int = 0
        self.recovery_start_time: float = 0
        self.recovery_end_time: float = 0
    
    def start_recovery(self, target_seq: int) -> Tuple[bool, str]:
        """开始恢复流程"""
        self.target_seq = target_seq
        self.recovery_start_time = time.time()
        
        # 准备恢复
        self.recovery_checkpoint, self.replay_count = self.checkpoint_manager.prepare_recovery(target_seq)
        
        if self.recovery_checkpoint is None and target_seq > 0:
            return False, "no checkpoint available for recovery"
        
        return True, "ok"
    
    def get_recovery_state(self) -> Tuple[int, str]:
        """
        获取恢复状态
        
        返回：
        - start_seq: 恢复起始seq
        - start_mem: 恢复起始memory
        """
        if self.recovery_checkpoint is None:
            return 0, ""
        
        return self.recovery_checkpoint.seq, self.recovery_checkpoint.memory
    
    def complete_recovery(self):
        """完成恢复"""
        self.recovery_end_time = time.time()
        
        recovery_latency_ms = (self.recovery_end_time - self.recovery_start_time) * 1000
        
        print(f"[CHECKPOINT] Recovery completed: "
              f"from_seq={self.recovery_checkpoint.seq if self.recovery_checkpoint else 0}, "
              f"to_seq={self.target_seq}, "
              f"replay_count={self.replay_count}, "
              f"latency_ms={recovery_latency_ms:.2f}")
    
    def get_recovery_statistics(self) -> Dict[str, Any]:
        """获取恢复统计信息"""
        recovery_latency_ms = 0
        if self.recovery_end_time > 0:
            recovery_latency_ms = (self.recovery_end_time - self.recovery_start_time) * 1000
        
        return {
            "target_seq": self.target_seq,
            "replay_count": self.replay_count,
            "recovery_latency_ms": round(recovery_latency_ms, 2),
            "checkpoint_seq": self.recovery_checkpoint.seq if self.recovery_checkpoint else 0,
            "checkpoint_storage_bytes": self.checkpoint_manager.get_storage_size(),
        }


def create_checkpoint_manager(session_id: str, epoch: int) -> CheckpointManager:
    """创建checkpoint管理器的工厂函数"""
    return CheckpointManager(session_id, epoch)


def demo_checkpoint_workflow():
    """演示checkpoint工作流程"""
    print("=" * 60)
    print("Checkpoint Manager Demo")
    print("=" * 60)
    
    # 创建checkpoint管理器
    manager = create_checkpoint_manager("demo-session", 1)
    
    # 模拟消息处理
    for seq in range(1, 26):
        memory = f"memory-state-{seq}"
        
        # 检查是否需要创建checkpoint
        if manager.should_checkpoint(seq):
            checkpoint = manager.create_checkpoint(seq, memory)
            print(f"Created checkpoint: seq={checkpoint.seq}")
    
    # 模拟恢复
    print("\n" + "=" * 60)
    print("Recovery Demo")
    print("=" * 60)
    
    recovery_session = CheckpointRecoverySession(manager)
    ok, reason = recovery_session.start_recovery(23)
    
    if ok:
        start_seq, start_mem = recovery_session.get_recovery_state()
        print(f"Recovery from seq={start_seq} to 23")
        print(f"Need to replay {recovery_session.replay_count} messages")
        
        # 模拟重放
        for seq in range(start_seq + 1, 24):
            print(f"Replaying message {seq}")
        
        recovery_session.complete_recovery()
    
    # 打印统计信息
    print("\n" + "=" * 60)
    print("Statistics")
    print("=" * 60)
    
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    recovery_stats = recovery_session.get_recovery_statistics()
    print("\nRecovery Statistics:")
    for key, value in recovery_stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    demo_checkpoint_workflow()
