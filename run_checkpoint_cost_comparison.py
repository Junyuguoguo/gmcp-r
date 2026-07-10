# -*- coding: utf-8 -*-
# run_checkpoint_cost_comparison.py
#
# O(k) vs O(n) Benchmark: Compare GMCP-R checkpoint recovery against
# Authenticated Hash Chain full-chain replay.
#
# Outputs checkpoint_cost_comparison.csv with 2160 rows (30 repeats).

import csv
import json
import os
import sys
import time
import hashlib
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from gmcp.config import DATA_AUTH_KEY, CHECKPOINT_AUTH_KEY
from gmcp.crypto_utils import hash_text, hmac_sha256_hex, verify_hmac, canonical_json, with_hmac, verify_tagged_hmac
from gmcp.memory import initial_memory, update_memory
from gmcp.baselines.authenticated_hash_chain import (
    build_data_packet as auth_chain_build_packet,
    verify_packet as auth_chain_verify_packet,
    hash_func,
    compute_chain_hash,
    create_initial_state as auth_chain_initial_state,
)
from gmcp.baselines.hash_chain import (
    create_initial_state as plain_chain_initial_state,
)
from gmcp.experiment_stats import get_git_commit


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PreparedHistory:
    """Persistent prepared history written as JSON Lines."""
    n: int
    k: int
    repeat_id: int
    workdir: str  # path to temp directory with history.jsonl
    checkpoint_seq: int
    checkpoint_mem: str
    checkpoint_record: Dict[str, Any]  # guaranteed non-None when k < n
    final_seq: int
    final_mem: str
    # chain state
    chain_checkpoint_hash: str
    chain_final_hash: str
    target_mem_by_seq: Dict[int, str]
    target_hash_by_seq: Dict[int, str]
    # file paths
    history_path: str
    chain_path: str


@dataclass
class RecoveryMeasurement:
    """Result of one timed recovery measurement."""
    protocol: str
    n: int
    k: int
    offset: int
    repeat_id: int
    replay_count: int
    recovery_material_bytes: int
    logical_bytes_read: int
    auth_records_verified: int
    recovery_time_ns: int
    target_seq: int
    reconstructed_mem: str
    reconstructed_hash: str
    target_state_match: bool
    checkpoint_auth_ok: bool = True
    record_auth_ok: bool = True
    chain_continuity_ok: bool = True
    payload_hash_ok: bool = True
    stored_mem_ok: bool = True
    recovery_valid: bool = True
    failure_reason: str = ""
    records_scanned: int = 0
    records_replayed: int = 0
    physical_bytes_read: int = 0
    logical_bytes_replayed: int = 0
    seek_offset: int = 0


# ---------------------------------------------------------------------------
# Prepare persistent history (JSON Lines)
# ---------------------------------------------------------------------------

def prepare_history(n: int, k: int, repeat_id: int, workdir: str) -> PreparedHistory:
    """
    Write deterministic JSON Lines history to workdir.

    Two files:
      - history.jsonl: GMCP protocol records (seq, payload, prev_mem, mem, auth_tag)
      - chain.jsonl: Authenticated Hash Chain records

    Checkpoint stored at seq = n - k with CHECKPOINT_AUTH_KEY signature.
    """
    checkpoint_seq = n - k
    session_id = f"cost-bench-{n}-{k}-{repeat_id}"
    sender_id = "bench-client"
    epoch = 1
    mem_seed = f"seed-{repeat_id}"

    history_path = os.path.join(workdir, "history.jsonl")
    chain_path = os.path.join(workdir, "chain.jsonl")

    # GMCP state
    mem = initial_memory(session_id, sender_id, epoch, mem_seed)
    checkpoint_record: Optional[Dict[str, Any]] = None
    checkpoint_mem = ""
    target_mem_by_seq: Dict[int, str] = {}

    # Auth chain state
    chain_state = auth_chain_initial_state(session_id, sender_id, epoch)
    chain_checkpoint_hash = ""
    target_hash_by_seq: Dict[int, str] = {}

    with open(history_path, "wb") as hf, \
         open(chain_path, "w", encoding="utf-8") as cf:

        # Track byte position after each GMCP line (for seek-based recovery)
        line_end_offsets: list[int] = []

        for seq in range(1, n + 1):
            payload = f"bench-payload-{repeat_id}-{seq}"
            payload_hash = hash_text(payload)

            # GMCP memory update
            new_mem = update_memory(mem, session_id, epoch, seq, payload_hash, sender_id)

            target_mem_by_seq[seq] = new_mem

            # Build GMCP record
            gmcp_record = {
                "seq": seq,
                "payload": payload,
                "payload_hash": payload_hash,
                "prev_mem": mem,
                "mem": new_mem,
                "session_id": session_id,
                "sender_id": sender_id,
                "epoch": epoch,
            }
            # Sign with DATA_AUTH_KEY
            gmcp_record = with_hmac(DATA_AUTH_KEY, gmcp_record, tag_field="auth_tag")
            raw = (canonical_json(gmcp_record) + '\n').encode('utf-8')
            hf.write(raw)
            line_end_offsets.append(hf.tell())

            # Store checkpoint at n-k
            if seq == checkpoint_seq:
                checkpoint_mem = new_mem
                checkpoint_record = {
                    "session_id": session_id,
                    "epoch": epoch,
                    "seq": checkpoint_seq,
                    "memory": checkpoint_mem,
                    "timestamp": time.time(),
                    # Byte offset of the END of the checkpoint line = start of next record
                    "log_byte_offset": line_end_offsets[checkpoint_seq - 1],
                    # Seq of the first record to replay after checkpoint
                    "next_seq": checkpoint_seq + 1,
                }
                checkpoint_record["signature"] = hmac_sha256_hex(
                    CHECKPOINT_AUTH_KEY, checkpoint_record
                )

            # Auth chain record
            auth_packet = auth_chain_build_packet(
                session_id, sender_id, epoch, seq,
                chain_state.last_hash, payload,
            )
            cf.write(canonical_json(auth_packet) + "\n")

            if seq == checkpoint_seq:
                chain_checkpoint_hash = auth_packet["chain_hash"]

            target_hash_by_seq[seq] = auth_packet["chain_hash"]

            # Update chain state
            chain_state.last_seq = seq
            chain_state.last_hash = auth_packet["chain_hash"]
            chain_state.hash_chain.append({
                "seq": seq,
                "hash": auth_packet["chain_hash"],
                "payload_hash": auth_packet["payload_hash"],
            })

            mem = new_mem

    assert checkpoint_record is not None, "checkpoint not created: k >= n?"

    return PreparedHistory(
        n=n,
        k=k,
        repeat_id=repeat_id,
        workdir=workdir,
        checkpoint_seq=checkpoint_seq,
        checkpoint_mem=checkpoint_mem,
        checkpoint_record=checkpoint_record,
        final_seq=n,
        final_mem=mem,
        chain_checkpoint_hash=chain_checkpoint_hash,
        chain_final_hash=chain_state.last_hash,
        target_mem_by_seq=target_mem_by_seq,
        target_hash_by_seq=target_hash_by_seq,
        history_path=history_path,
        chain_path=chain_path,
    )


# ---------------------------------------------------------------------------
# Measure GMCP-R recovery (O(k))
# ---------------------------------------------------------------------------

def measure_gmcp_recovery(prepared: PreparedHistory, offset: int) -> RecoveryMeasurement:
    """
    GMCP-R recovery: seek-based O(k) recovery.
    Use binary seek to skip to checkpoint position, then replay `offset` messages.
    replay_count = offset
    """
    target_seq = prepared.checkpoint_seq + offset
    session_id = f"cost-bench-{prepared.n}-{prepared.k}-{prepared.repeat_id}"

    # Warmup (unrecorded): read checkpoint once
    _ = prepared.checkpoint_record

    # Timed recovery
    t0 = time.perf_counter_ns()

    # 1. Read checkpoint (material bytes = serialized checkpoint)
    checkpoint_bytes = len(canonical_json(prepared.checkpoint_record).encode("utf-8"))
    sig_data = dict(prepared.checkpoint_record)
    sig = sig_data.pop("signature", "")
    ck_ok = verify_hmac(CHECKPOINT_AUTH_KEY, sig_data, sig)

    # If checkpoint auth fails, return failure measurement immediately
    if not ck_ok:
        t1 = time.perf_counter_ns()
        return RecoveryMeasurement(
            protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
            repeat_id=prepared.repeat_id, replay_count=0,
            recovery_material_bytes=checkpoint_bytes,
            logical_bytes_read=checkpoint_bytes,
            auth_records_verified=1,
            recovery_time_ns=t1 - t0,
            target_seq=target_seq,
            reconstructed_mem="", reconstructed_hash="",
            target_state_match=False,
            checkpoint_auth_ok=False, record_auth_ok=True,
            chain_continuity_ok=True, payload_hash_ok=True,
            recovery_valid=False,
            failure_reason="checkpoint_auth_failed",
        )

    # 2. Seek-based replay: binary seek to checkpoint's log_byte_offset
    seek_offset = prepared.checkpoint_record["log_byte_offset"]
    reconstructed_mem = prepared.checkpoint_record["memory"]
    prev_mem = reconstructed_mem
    replay_count = 0
    records_scanned = 0
    material_bytes = checkpoint_bytes
    logical_bytes = checkpoint_bytes
    auth_records = 1  # checkpoint verification
    physical_bytes = 0
    logical_bytes_replayed = 0
    sender_id = "bench-client"
    epoch = 1

    with open(prepared.history_path, "rb") as f:
        f.seek(seek_offset)
        for _expected_index in range(offset):
            raw = f.readline()
            if not raw:
                t1 = time.perf_counter_ns()
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes,
                    logical_bytes_read=logical_bytes,
                    auth_records_verified=auth_records,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    stored_mem_ok=True,
                    recovery_valid=False,
                    failure_reason=f"unexpected_eof_after_{records_scanned}_records",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )
            physical_bytes += len(raw)
            line = raw.decode("utf-8").rstrip("\n")
            record = json.loads(line)
            seq = record["seq"]
            records_scanned += 1

            # Verify auth_tag
            received_tag = record.pop("auth_tag", "")
            unsigned = dict(record)
            tag_ok = verify_hmac(DATA_AUTH_KEY, unsigned, received_tag)
            record["auth_tag"] = received_tag

            if not tag_ok:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"record_auth_failed_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            # Verify session_id, sender_id, epoch
            if record.get("session_id") != session_id:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"session_id_mismatch_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            if record.get("sender_id") != sender_id:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"sender_id_mismatch_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            if record.get("epoch") != epoch:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"epoch_mismatch_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            # Verify seq continuity
            expected_seq = prepared.checkpoint_seq + replay_count + 1
            if record["seq"] != expected_seq:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=False, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"seq_continuity_failed_seq_{seq}_expected_{expected_seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            # Verify prev_mem chain continuity
            chain_ok = (record["prev_mem"] == prev_mem)
            if not chain_ok:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=False, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"chain_continuity_failed_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            # Verify payload_hash
            computed_hash = hash_text(record["payload"])
            ph_ok = (computed_hash == record["payload_hash"])
            if not ph_ok:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=True, payload_hash_ok=False,
                    recovery_valid=False,
                    failure_reason=f"payload_hash_failed_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )

            # Reconstruct memory via update_memory() (not reading stored mem)
            reconstructed_mem = update_memory(
                prev_mem, session_id, record["epoch"],
                record["seq"], record["payload_hash"], record["sender_id"],
            )
            stored_mem_ok = (reconstructed_mem == record.get("mem"))
            if not stored_mem_ok:
                t1 = time.perf_counter_ns()
                line_bytes = len(raw)
                return RecoveryMeasurement(
                    protocol="gmcp_r", n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem=reconstructed_mem, reconstructed_hash="",
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    stored_mem_ok=False,
                    recovery_valid=False,
                    failure_reason=f"stored_mem_failed_seq_{seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=seek_offset,
                )
            prev_mem = reconstructed_mem
            replay_count += 1
            line_bytes = len(raw)
            material_bytes += line_bytes
            logical_bytes += line_bytes
            auth_records += 1
            logical_bytes_replayed += line_bytes

    t1 = time.perf_counter_ns()

    # Target state: compare against pre-computed target from prepare_history
    target_mem = prepared.target_mem_by_seq.get(target_seq, "")
    target_state_match = (reconstructed_mem == target_mem)
    # recovery_valid: all checks passed AND state matches AND counts correct
    recovery_valid = (
        target_state_match
        and replay_count == offset
        and records_scanned == offset
    )

    return RecoveryMeasurement(
        protocol="gmcp_r",
        n=prepared.n,
        k=prepared.k,
        offset=offset,
        repeat_id=prepared.repeat_id,
        replay_count=replay_count,
        recovery_material_bytes=material_bytes,
        logical_bytes_read=logical_bytes,
        auth_records_verified=auth_records,
        recovery_time_ns=t1 - t0,
        target_seq=target_seq,
        reconstructed_mem=reconstructed_mem,
        reconstructed_hash="",  # not applicable for GMCP
        target_state_match=target_state_match,
        checkpoint_auth_ok=True, record_auth_ok=True,
        chain_continuity_ok=True, payload_hash_ok=True, stored_mem_ok=True,
        recovery_valid=recovery_valid, failure_reason="",
        records_scanned=records_scanned, records_replayed=replay_count,
        physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
        seek_offset=seek_offset,
    )


# ---------------------------------------------------------------------------
# Measure Authenticated Hash Chain recovery (O(n))
# ---------------------------------------------------------------------------

def measure_authenticated_chain_recovery(prepared: PreparedHistory, offset: int) -> RecoveryMeasurement:
    """
    Authenticated Hash Chain recovery: read full chain from 1 to target_seq.
    replay_count = target_seq
    """
    target_seq = prepared.checkpoint_seq + offset
    session_id = f"cost-bench-{prepared.n}-{prepared.k}-{prepared.repeat_id}"
    sender_id = "bench-client"
    epoch = 1

    # Warmup
    initial_state = auth_chain_initial_state(session_id, sender_id, epoch)
    _ = initial_state.last_hash

    # Timed recovery
    t0 = time.perf_counter_ns()

    current_hash = initial_state.last_hash
    replay_count = 0
    material_bytes = 0
    logical_bytes = 0
    auth_records = 0
    reconstructed_hash = current_hash
    records_scanned = 0
    physical_bytes = 0
    logical_bytes_replayed = 0

    with open(prepared.chain_path, "r", encoding="utf-8") as f:
        for expected_seq in range(1, target_seq + 1):
            line = f.readline()
            if not line:
                t1 = time.perf_counter_ns()
                return RecoveryMeasurement(
                    protocol="authenticated_hash_chain",
                    n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes,
                    logical_bytes_read=logical_bytes,
                    auth_records_verified=auth_records,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem="", reconstructed_hash=reconstructed_hash,
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=True,
                    chain_continuity_ok=True, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"unexpected_eof_after_{records_scanned}_records",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=0,
                )
            line_bytes = len(line.encode("utf-8"))
            physical_bytes += line_bytes
            packet = json.loads(line)
            seq = packet["seq"]
            records_scanned += 1
            if seq != expected_seq:
                t1 = time.perf_counter_ns()
                return RecoveryMeasurement(
                    protocol="authenticated_hash_chain",
                    n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem="", reconstructed_hash=reconstructed_hash,
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=False, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"seq_continuity_failed_seq_{seq}_expected_{expected_seq}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=0,
                )

            # Verify: HMAC + chain hash + prev_hash
            ok, reason = auth_chain_verify_packet(
                packet=packet,
                expected_session_id=session_id,
                expected_sender_id=sender_id,
                expected_epoch=epoch,
                last_hash=current_hash,
            )

            if not ok:
                t1 = time.perf_counter_ns()
                return RecoveryMeasurement(
                    protocol="authenticated_hash_chain",
                    n=prepared.n, k=prepared.k, offset=offset,
                    repeat_id=prepared.repeat_id, replay_count=replay_count,
                    recovery_material_bytes=material_bytes + line_bytes,
                    logical_bytes_read=logical_bytes + line_bytes,
                    auth_records_verified=auth_records + 1,
                    recovery_time_ns=t1 - t0,
                    target_seq=target_seq,
                    reconstructed_mem="", reconstructed_hash=reconstructed_hash,
                    target_state_match=False,
                    checkpoint_auth_ok=True, record_auth_ok=False,
                    chain_continuity_ok=False, payload_hash_ok=True,
                    recovery_valid=False,
                    failure_reason=f"chain_verify_failed_seq_{seq}_{reason}",
                    records_scanned=records_scanned, records_replayed=replay_count,
                    physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
                    seek_offset=0,
                )

            current_hash = packet["chain_hash"]
            reconstructed_hash = current_hash
            replay_count += 1
            material_bytes += line_bytes
            logical_bytes += line_bytes
            auth_records += 1
            logical_bytes_replayed += line_bytes

    t1 = time.perf_counter_ns()

    target_state_match = (reconstructed_hash == prepared.target_hash_by_seq.get(target_seq, ""))
    recovery_valid = (
        target_state_match
        and replay_count == target_seq
        and records_scanned == target_seq
    )

    return RecoveryMeasurement(
        protocol="authenticated_hash_chain",
        n=prepared.n,
        k=prepared.k,
        offset=offset,
        repeat_id=prepared.repeat_id,
        replay_count=replay_count,
        recovery_material_bytes=material_bytes,
        logical_bytes_read=logical_bytes,
        auth_records_verified=auth_records,
        recovery_time_ns=t1 - t0,
        target_seq=target_seq,
        reconstructed_mem="",  # not applicable for chain
        reconstructed_hash=reconstructed_hash,
        target_state_match=target_state_match,
        checkpoint_auth_ok=True, record_auth_ok=True,
        chain_continuity_ok=True, payload_hash_ok=True,
        recovery_valid=recovery_valid, failure_reason="",
        records_scanned=records_scanned, records_replayed=replay_count,
        physical_bytes_read=physical_bytes, logical_bytes_replayed=logical_bytes_replayed,
        seek_offset=0,
    )


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "protocol", "n", "k", "offset", "repeat_id",
    "replay_count", "recovery_material_bytes", "logical_bytes_read",
    "auth_records_verified", "recovery_time_ns",
    "recovery_time_us", "recovery_time_ms",
    "target_seq", "reconstructed_mem", "reconstructed_hash",
    "target_state_match",
    "checkpoint_auth_ok", "record_auth_ok", "chain_continuity_ok",
    "payload_hash_ok", "stored_mem_ok", "recovery_valid", "failure_reason",
    "records_scanned", "records_replayed", "physical_bytes_read",
    "logical_bytes_replayed", "seek_offset", "git_commit",
]


def measurement_to_row(m: RecoveryMeasurement) -> Dict[str, Any]:
    return {
        "protocol": m.protocol,
        "n": m.n,
        "k": m.k,
        "offset": m.offset,
        "repeat_id": m.repeat_id,
        "replay_count": m.replay_count,
        "recovery_material_bytes": m.recovery_material_bytes,
        "logical_bytes_read": m.logical_bytes_read,
        "auth_records_verified": m.auth_records_verified,
        "recovery_time_ns": m.recovery_time_ns,
        "recovery_time_us": round(m.recovery_time_ns / 1000, 3),
        "recovery_time_ms": round(m.recovery_time_ns / 1_000_000, 6),
        "target_seq": m.target_seq,
        "reconstructed_mem": m.reconstructed_mem,
        "reconstructed_hash": m.reconstructed_hash,
        "target_state_match": m.target_state_match,
        "checkpoint_auth_ok": m.checkpoint_auth_ok,
        "record_auth_ok": m.record_auth_ok,
        "chain_continuity_ok": m.chain_continuity_ok,
        "payload_hash_ok": m.payload_hash_ok,
        "stored_mem_ok": m.stored_mem_ok,
        "recovery_valid": m.recovery_valid,
        "failure_reason": m.failure_reason,
        "records_scanned": m.records_scanned,
        "records_replayed": m.records_replayed,
        "physical_bytes_read": m.physical_bytes_read,
        "logical_bytes_replayed": m.logical_bytes_replayed,
        "seek_offset": m.seek_offset,
        "git_commit": get_git_commit(),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Environment overrides
    n_values = [int(x) for x in os.getenv("GMCP_SESSION_LENGTHS", "1000,10000,100000").split(",")]
    k_values = [int(x) for x in os.getenv("GMCP_CHECKPOINT_INTERVALS", "10,50,100,500").split(",")]
    repeats = int(os.getenv("GMCP_REPEATS", "30"))
    output_root = os.getenv("GMCP_OUTPUT_ROOT", "results/submission_revision")

    os.makedirs(output_root, exist_ok=True)
    csv_path = os.path.join(output_root, "checkpoint_cost_comparison.csv")

    total_rows = 0
    invalid_rows: List[RecoveryMeasurement] = []

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_COLUMNS)
        writer.writeheader()

        for n in n_values:
            for k in k_values:
                if k >= n:
                    continue  # checkpoint must be before end

                offsets = [1, k // 2, k - 1]
                # Deduplicate offsets (e.g. k=2 → [1, 1, 1])
                offsets = sorted(set(offsets))

                for repeat_id in range(1, repeats + 1):
                    # Prepare history in temp directory
                    with tempfile.TemporaryDirectory(prefix=f"gmcp_cost_{n}_{k}_{repeat_id}_") as workdir:
                        prepared = prepare_history(n, k, repeat_id, workdir)

                        for offset in offsets:
                            # GMCP-R
                            gmcp_m = measure_gmcp_recovery(prepared, offset)
                            writer.writerow(measurement_to_row(gmcp_m))
                            total_rows += 1
                            if not gmcp_m.recovery_valid:
                                invalid_rows.append(gmcp_m)

                            # Authenticated Hash Chain
                            chain_m = measure_authenticated_chain_recovery(prepared, offset)
                            writer.writerow(measurement_to_row(chain_m))
                            total_rows += 1
                            if not chain_m.recovery_valid:
                                invalid_rows.append(chain_m)

                    if repeat_id % 5 == 0 or repeat_id == repeats:
                        print(f"  n={n}, k={k}, repeat={repeat_id}/{repeats}, rows so far={total_rows}")

    print(f"\nDone. {total_rows} rows written to {csv_path}")

    # Full matrix: 3 n × 4 k × 3 offsets × 2 protocols × 30 repeats = 2160
    expected_full = 3 * 4 * 3 * 2 * 30
    if total_rows != expected_full and repeats == 30 and len(n_values) == 3 and len(k_values) == 4:
        print(f"WARNING: Expected {expected_full} rows, got {total_rows}", file=sys.stderr)
        return 1

    if invalid_rows:
        print("[CHECKPOINT_COST] INVALID RESULTS:", file=sys.stderr)
        for row in invalid_rows[:20]:
            print(
                f"  - protocol={row.protocol} n={row.n} k={row.k} offset={row.offset} "
                f"repeat={row.repeat_id} reason={row.failure_reason}",
                file=sys.stderr,
            )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
