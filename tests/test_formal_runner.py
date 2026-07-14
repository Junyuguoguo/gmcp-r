# -*- coding: utf-8 -*-
# tests/test_formal_runner.py
#
# Tests that exercise run_cross_host_validation.run_one_experiment and its
# direct dependencies (gmcp.experiment_transport) without requiring a live
# external server.  Each test targets runner or transport behaviour only;
# low-level crypto / packet / attack / ticket tests live elsewhere.
#
# NEW: Tests for the aggregator (aggregate_cross_host_batches.validate_all)
# and additional runner edge-case coverage.

import csv
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from gmcp.experiment_transport import (
    ProtocolAdapter,
    send_hello,
    send_json_line,
    recv_json_line,
    WIRE_PROTOCOL_NAMES,
)
from gmcp.memory import initial_memory, update_memory
from gmcp.crypto_utils import hash_text


# ---------------------------------------------------------------------------
# 1. TCP connect timeout → structured failure dict (never None)
# ---------------------------------------------------------------------------

class TestTCPConnectTimeoutStructuredFailure(unittest.TestCase):
    """run_one_experiment must return a structured failure row on TCP timeout."""

    def test_open_tcp_timeout_returns_structured_failure(self):
        import run_cross_host_validation as runner

        with patch.object(runner, "open_tcp", side_effect=socket.timeout("timed out")):
            result = runner.run_one_experiment(
                protocol="gmcp_r",
                message_count=10,
                payload_size=128,
                repeat_id=1,
                server_host="127.0.0.1",
                server_port=9999,
                client_host_id="test-client",
                server_host_id="test-server",
                network_path_type="loopback",
                baseline_rtt_ms=1.0,
                git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
            )
        self.assertIsNotNone(result, "Result must not be None on TCP timeout")
        self.assertIsInstance(result, dict)
        self.assertFalse(result.get("run_valid", True))
        self.assertNotEqual(result.get("failure_reason", ""), "")
        self.assertEqual(result.get("accepted_count", 0), 0)
        self.assertEqual(result.get("sent_count", 0), 0)

    def test_hello_failure_returns_structured_failure(self):
        """If HELLO handshake fails, run_one_experiment returns run_valid=False."""
        import run_cross_host_validation as runner

        mock_sock = MagicMock()
        mock_file = MagicMock()
        # open_tcp returns mock socket
        with patch.object(runner, "open_tcp", return_value=(mock_sock, mock_file)):
            # send_hello raises on HELLO rejection
            with patch("run_cross_host_validation.send_hello", side_effect=RuntimeError("HELLO rejected")):
                result = runner.run_one_experiment(
                    protocol="gmcp_r",
                    message_count=10,
                    payload_size=128,
                    repeat_id=1,
                    server_host="127.0.0.1",
                    server_port=9999,
                    client_host_id="test-client",
                    server_host_id="test-server",
                    network_path_type="loopback",
                    baseline_rtt_ms=1.0,
                    git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
                )
        self.assertFalse(result.get("run_valid", True))
        self.assertIn("HELLO", result.get("failure_reason", "").upper())


# ---------------------------------------------------------------------------
# 2. HELLO handshake: wire protocol name mapping & mismatch detection
# ---------------------------------------------------------------------------

class TestHelloHandshakeProtocolNegotiation(unittest.TestCase):
    """send_hello maps gmcp_r→gmcp on the wire and rejects mismatches."""

    def test_send_hello_maps_gmcp_r_to_gmcp_wire_name(self):
        mock_sock = MagicMock()
        expected_wire = WIRE_PROTOCOL_NAMES["gmcp_r"]
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": expected_wire,
            "session_id": "test-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        result = send_hello(
            mock_sock, mock_file, "gmcp_r", "test-session", "client-1", 1
        )
        self.assertEqual(result["protocol"], "gmcp")

        # Inspect the HELLO that was sent
        sent_raw = mock_sock.sendall.call_args[0][0]
        sent_msg = json.loads(sent_raw.decode("utf-8").strip())
        self.assertEqual(sent_msg["type"], "HELLO")
        self.assertEqual(sent_msg["protocol"], "gmcp")
        self.assertIn("auth_tag", sent_msg)

    def test_send_hello_rejects_mismatched_ack_protocol(self):
        mock_sock = MagicMock()
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": "wrong_proto",
            "session_id": "test-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        with self.assertRaises(RuntimeError) as ctx:
            send_hello(mock_sock, mock_file, "gmcp_r", "test-session", "c1", 1)
        self.assertIn("protocol mismatch", str(ctx.exception).lower())

    def test_send_hello_rejects_mismatched_session_id(self):
        mock_sock = MagicMock()
        ack = {
            "type": "HELLO_ACK",
            "ok": True,
            "protocol": "gmcp",
            "session_id": "wrong-session",
        }
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        with self.assertRaises(RuntimeError) as ctx:
            send_hello(mock_sock, mock_file, "gmcp_r", "test-session", "c1", 1)
        self.assertIn("session_id", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# 3. ProtocolAdapter: independent state tracking & mismatch detection
# ---------------------------------------------------------------------------

class TestProtocolAdapterStateTracking(unittest.TestCase):
    """ProtocolAdapter tracks client state independently after accept."""

    def test_gmcp_r_adapter_builds_valid_packet(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload-1")
        self.assertIn("prev_mem", pkt)
        self.assertIn("auth_tag", pkt)
        self.assertEqual(pkt["protocol"], "gmcp")

    def test_adapter_update_tracks_state_independently(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload-1")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        response = {"ok": True, "last_seq": 1, "last_mem": new_mem}
        adapter.update_after_accept(pkt, response)

        self.assertEqual(adapter.last_seq, 1)
        self.assertEqual(adapter.client_state["last_mem"], new_mem)

    def test_adapter_state_match_detects_match(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})
        self.assertTrue(adapter.check_state_match())

    def test_adapter_state_match_detects_mismatch(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        new_mem = update_memory(
            adapter.client_state["last_mem"],
            "s1", 1, 1, pkt["payload_hash"], "c1",
        )
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})
        self.assertFalse(adapter.check_state_match({"last_seq": 1, "last_mem": "wrong"}))

    def test_adapter_multi_seq_state_chain(self):
        """Adapter correctly chains state across multiple packets."""
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        for seq in range(1, 6):
            payload = f"msg-{seq}"
            pkt = adapter.build_packet(seq, payload)
            new_mem = update_memory(
                adapter.client_state["last_mem"],
                "s1", 1, seq, pkt["payload_hash"], "c1",
            )
            adapter.update_after_accept(pkt, {"ok": True, "last_seq": seq, "last_mem": new_mem})

        self.assertEqual(adapter.last_seq, 5)
        self.assertTrue(adapter.check_state_match())
        # All memories should be unique across the chain
        self.assertNotEqual(adapter._initial_mem, adapter.client_state["last_mem"])


# ---------------------------------------------------------------------------
# 4. JSON line transport: round-trip, EOF, malformed
# ---------------------------------------------------------------------------

class TestJSONLineTransport(unittest.TestCase):
    """send_json_line / recv_json_line round-trip and error handling."""

    def test_send_recv_roundtrip(self):
        mock_sock = MagicMock()
        data = {"type": "TEST", "value": 42}
        send_json_line(mock_sock, data)

        sent_bytes = mock_sock.sendall.call_args[0][0]
        self.assertTrue(sent_bytes.endswith(b"\n"))
        parsed = json.loads(sent_bytes.decode("utf-8").strip())
        self.assertEqual(parsed["type"], "TEST")
        self.assertEqual(parsed["value"], 42)

    def test_recv_json_line_raises_on_eof(self):
        mock_file = MagicMock()
        mock_file.readline.return_value = ""  # EOF

        with self.assertRaises(ConnectionError):
            recv_json_line(mock_file)

    def test_recv_json_line_raises_on_malformed_json(self):
        mock_file = MagicMock()
        mock_file.readline.return_value = "not-json\n"

        with self.assertRaises(json.JSONDecodeError):
            recv_json_line(mock_file)

    def test_send_json_line_preserves_unicode(self):
        mock_sock = MagicMock()
        data = {"msg": "你好世界"}
        send_json_line(mock_sock, data)

        sent_bytes = mock_sock.sendall.call_args[0][0]
        parsed = json.loads(sent_bytes.decode("utf-8").strip())
        self.assertEqual(parsed["msg"], "你好世界")


# ---------------------------------------------------------------------------
# 5. Integration: run_one_experiment against embedded server (loopback)
# ---------------------------------------------------------------------------

class TestRunnerWithEmbeddedServer(unittest.TestCase):
    """run_one_experiment against a real EmbeddedTCPServer on loopback."""

    @classmethod
    def setUpClass(cls):
        import run_cross_host_validation as runner
        cls._runner = runner
        cls._port = 19876  # fixed port for deterministic tests
        cls._server = runner.EmbeddedTCPServer("127.0.0.1", cls._port)
        cls._server.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls._server.stop()
        time.sleep(0.1)

    def _run(self, protocol, message_count=5, payload_size=64):
        git_meta = {
            "git_commit": "a" * 40,
            "git_branch": "main",
            "git_dirty": "false",
            "client_cpu_model": "test",
        }
        return self._runner.run_one_experiment(
            protocol=protocol,
            message_count=message_count,
            payload_size=payload_size,
            repeat_id=1,
            server_host="127.0.0.1",
            server_port=self._port,
            client_host_id="test-client",
            server_host_id="test-server",
            network_path_type="loopback",
            baseline_rtt_ms=0.5,
            git_meta=git_meta,
        )

    def test_gmcp_r_integration(self):
        result = self._run("gmcp_r")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)
        self.assertEqual(result["sent_count"], 5)
        self.assertTrue(result["state_match"])
        self.assertTrue(result["sequence_match"])

    def test_seq_mac_integration(self):
        result = self._run("seq_mac")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)

    def test_hash_chain_integration(self):
        result = self._run("hash_chain")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)
        self.assertTrue(result["hash_match"])

    def test_ticket_only_integration(self):
        result = self._run("ticket_only")
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 5)

    def test_result_has_all_csv_fields(self):
        result = self._run("gmcp_r", message_count=2, payload_size=32)
        required_keys = {
            "session_id", "protocol", "client_host_id", "server_host_id",
            "network_path_type", "accepted_count", "rejected_count",
            "run_valid", "state_match", "sequence_match",
            "avg_rtt_ms", "p50_rtt_ms", "p95_rtt_ms", "p99_rtt_ms",
            "client_final_seq", "server_final_seq",
            "client_final_mem", "server_final_mem",
        }
        self.assertTrue(required_keys.issubset(result.keys()), f"Missing keys: {required_keys - result.keys()}")


# ===========================================================================
# NEW TESTS (6-12): Aggregator + Runner edge cases
# ===========================================================================


# ---------------------------------------------------------------------------
# Helper: build a minimal valid batch CSV
# ---------------------------------------------------------------------------

def _make_row(repeat_id=1, protocol="gmcp_r", message_count=500, payload_size=128,
              run_valid="True", accepted=None, rejected=0, timeout=0, error=0,
              git_commit="a" * 40, git_dirty="false", server_git_dirty="false",
              session_id=None, memory_match="True", hash_match="",
              state_match="True", sequence_match="True",
              server_hostname="ser5181800568", server_python_version="3.9.16",
              server_os_info="CentOS 7.6", server_cpu_model="x86_64",
              server_git_commit="a" * 40, network_path_type="wan",
              client_host_id="VM-0-14-ubuntu", failure_reason="",
              unrecovered=0):
    """Build a single result dict matching the expected CSV schema."""
    if accepted is None:
        accepted = message_count
    if session_id is None:
        session_id = f"cross-{protocol}-m{message_count}-p{payload_size}-r{repeat_id}-{repeat_id:04d}"
    return {
        "session_id": session_id,
        "protocol": protocol,
        "message_count": str(message_count),
        "payload_size": str(payload_size),
        "repeat_id": str(repeat_id),
        "run_valid": run_valid,
        "accepted_count": str(accepted),
        "rejected_count": str(rejected),
        "timeout_count": str(timeout),
        "error_count": str(error),
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "server_git_dirty": server_git_dirty,
        "memory_match": memory_match,
        "hash_match": hash_match,
        "state_match": state_match,
        "sequence_match": sequence_match,
        "server_hostname": server_hostname,
        "server_python_version": server_python_version,
        "server_os_info": server_os_info,
        "server_cpu_model": server_cpu_model,
        "server_git_commit": server_git_commit,
        "network_path_type": network_path_type,
        "client_host_id": client_host_id,
        "failure_reason": failure_reason,
        "unrecovered": str(unrecovered),
        "sent_count": str(accepted + rejected + timeout + error),
    }


def _make_batch_csv(path: Path, repeat_id: int, rows: "list[dict] | None" = None):
    """Write a batch CSV with the given rows (or a valid default set)."""
    if rows is None:
        rows = []
        for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
            for mc in [500, 1000]:
                for ps in [128, 512]:
                    hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                    mm = "True" if proto == "gmcp_r" else ""
                    rows.append(_make_row(
                        repeat_id=repeat_id, protocol=proto,
                        message_count=mc, payload_size=ps,
                        memory_match=mm, hash_match=hm,
                        session_id=f"cross-{proto}-m{mc}-p{ps}-r{repeat_id}-{repeat_id:04d}",
                    ))
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# 6. Aggregator: validate_all happy path
# ---------------------------------------------------------------------------

class TestAggregatorHappyPath(unittest.TestCase):
    """validate_all passes with 20 valid batch CSVs."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.batch_dir = Path(self.tmpdir) / "batches"
        self.batch_dir.mkdir()
        for rid in range(1, 21):
            _make_batch_csv(self.batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)

    def test_validate_all_passes(self):
        from aggregate_cross_host_batches import validate_all
        errors, all_rows, _ = validate_all(self.batch_dir)
        self.assertEqual(errors, [], f"Unexpected errors: {errors}")
        self.assertEqual(len(all_rows), 400)

    def test_aggregate_produces_correct_output(self):
        """End-to-end: aggregate writes 400 rows to output CSV."""
        import subprocess, sys as _sys
        output = Path(self.tmpdir) / "results.csv"
        result = subprocess.run(
            [_sys.executable, "aggregate_cross_host_batches.py",
             "--batch-dir", str(self.batch_dir),
             "--output", str(output)],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))) or ".",
        )
        self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
        self.assertTrue(output.exists())
        with output.open() as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 400)


# ---------------------------------------------------------------------------
# 7. Aggregator: wrong batch file count (V01)
# ---------------------------------------------------------------------------

class TestAggregatorV01BatchFileCount(unittest.TestCase):
    """V01: exactly 20 batch files required."""

    def test_too_few_files_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 5):  # only 4 files
            _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V01" in e for e in errors), f"Expected V01 error, got: {errors}")

    def test_too_many_files_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 22):  # 21 files
            _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V01" in e for e in errors), f"Expected V01 error, got: {errors}")


# ---------------------------------------------------------------------------
# 8. Aggregator: duplicate repeat IDs (V03)
# ---------------------------------------------------------------------------

class TestAggregatorV03DuplicateRepeatIds(unittest.TestCase):
    """V03: duplicate repeat_id in filenames must fail."""

    def test_duplicate_rid_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        # r01 twice, skip r20
        for rid in list(range(1, 20)) + [1]:
            _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(len(errors) > 0, f"Expected validation errors, got: {errors}")


# ---------------------------------------------------------------------------
# 9. Aggregator: wrong row count per batch (V04)
# ---------------------------------------------------------------------------

class TestAggregatorV04RowCount(unittest.TestCase):
    """V04: each batch must have exactly 20 rows."""

    def test_too_few_rows_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 5:
                # Only 10 rows for batch 5
                rows = [_make_row(repeat_id=5, session_id=f"s-{i}") for i in range(10)]
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("expected 20 rows" in e for e in errors), f"Expected row count error, got: {errors}")


# ---------------------------------------------------------------------------
# 10. Aggregator: run_valid=False detected (V06)
# ---------------------------------------------------------------------------

class TestAggregatorV06RunValid(unittest.TestCase):
    """V06: any row with run_valid=False must fail."""

    def test_invalid_run_valid_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                # First batch has one bad row
                rows = []
                for j, (proto, mc, ps) in enumerate([
                    ("gmcp_r", 500, 128), ("gmcp_r", 500, 512),
                    ("gmcp_r", 1000, 128), ("gmcp_r", 1000, 512),
                    ("hash_chain", 500, 128), ("hash_chain", 500, 512),
                    ("hash_chain", 1000, 128), ("hash_chain", 1000, 512),
                    ("authenticated_hash_chain", 500, 128), ("authenticated_hash_chain", 500, 512),
                    ("authenticated_hash_chain", 1000, 128), ("authenticated_hash_chain", 1000, 512),
                    ("seq_mac", 500, 128), ("seq_mac", 500, 512),
                    ("seq_mac", 1000, 128), ("seq_mac", 1000, 512),
                    ("ticket_only", 500, 128), ("ticket_only", 500, 512),
                    ("ticket_only", 1000, 128), ("ticket_only", 1000, 512),
                ]):
                    rv = "False" if j == 0 else "True"
                    hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                    mm = "True" if proto == "gmcp_r" else ""
                    rows.append(_make_row(
                        repeat_id=1, protocol=proto, message_count=mc,
                        payload_size=ps, run_valid=rv,
                        memory_match=mm, hash_match=hm,
                        session_id=f"bad-{proto}-{j}",
                    ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("run_valid=False" in e for e in errors), f"Expected run_valid error, got: {errors}")


# ---------------------------------------------------------------------------
# 11. Aggregator: rejected_count > 0 detected (V08)
# ---------------------------------------------------------------------------

class TestAggregatorV08Unrecovered(unittest.TestCase):
    """V08: rejected/timeout/error > 0 must fail."""

    def test_rejected_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 3:
                rows = []
                for j, (proto, mc, ps) in enumerate([
                    ("gmcp_r", 500, 128), ("gmcp_r", 500, 512),
                    ("gmcp_r", 1000, 128), ("gmcp_r", 1000, 512),
                    ("hash_chain", 500, 128), ("hash_chain", 500, 512),
                    ("hash_chain", 1000, 128), ("hash_chain", 1000, 512),
                    ("authenticated_hash_chain", 500, 128), ("authenticated_hash_chain", 500, 512),
                    ("authenticated_hash_chain", 1000, 128), ("authenticated_hash_chain", 1000, 512),
                    ("seq_mac", 500, 128), ("seq_mac", 500, 512),
                    ("seq_mac", 1000, 128), ("seq_mac", 1000, 512),
                    ("ticket_only", 500, 128), ("ticket_only", 500, 512),
                    ("ticket_only", 1000, 128), ("ticket_only", 1000, 512),
                ]):
                    rej = 1 if j == 0 else 0
                    hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                    mm = "True" if proto == "gmcp_r" else ""
                    rows.append(_make_row(
                        repeat_id=3, protocol=proto, message_count=mc,
                        payload_size=ps, rejected=rej,
                        memory_match=mm, hash_match=hm,
                        session_id=f"rej-{proto}-{j}",
                    ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("unrecovered" in e for e in errors), f"Expected unrecovered error, got: {errors}")


# ---------------------------------------------------------------------------
# 12. Aggregator: duplicate session_ids (V17)
# ---------------------------------------------------------------------------

class TestAggregatorV17DuplicateSessionIds(unittest.TestCase):
    """V17: duplicate session_ids must fail."""

    def test_duplicate_session_id_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                # Give all rows the same session_id
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                session_id="duplicate-session",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V17" in e for e in errors), f"Expected V17 error, got: {errors}")


# ---------------------------------------------------------------------------
# 13. Runner: connection refused → structured failure (never None)
# ---------------------------------------------------------------------------

class TestRunnerConnectionRefused(unittest.TestCase):
    """ConnectionRefusedError must return structured failure, not raise."""

    def test_connection_refused_returns_structured_failure(self):
        import run_cross_host_validation as runner

        with patch.object(runner, "open_tcp", side_effect=ConnectionRefusedError("refused")):
            result = runner.run_one_experiment(
                protocol="seq_mac",
                message_count=10,
                payload_size=128,
                repeat_id=1,
                server_host="127.0.0.1",
                server_port=9999,
                client_host_id="test-client",
                server_host_id="test-server",
                network_path_type="loopback",
                baseline_rtt_ms=1.0,
                git_meta={"git_commit": "b" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
            )
        self.assertIsNotNone(result)
        self.assertFalse(result.get("run_valid", True))
        self.assertIn("refused", result.get("failure_reason", "").lower())


# ---------------------------------------------------------------------------
# 14. Runner: mid-run timeout → partial results preserved
# ---------------------------------------------------------------------------

class TestRunnerMidRunTimeout(unittest.TestCase):
    """Timeout mid-run stops iteration, preserves partial accepted_count."""

    def test_timeout_stops_iteration(self):
        import run_cross_host_validation as runner
        call_count = 0

        def mock_recv(file_obj):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                return {"ok": True, "last_seq": call_count, "last_mem": f"mem-{call_count}"}
            else:
                raise socket.timeout("timed out")

        mock_sock = MagicMock()
        mock_file = MagicMock()

        with patch.object(runner, "open_tcp", return_value=(mock_sock, mock_file)):
            with patch("run_cross_host_validation.send_hello", return_value={
                "ok": True, "type": "HELLO_ACK", "protocol": "gmcp",
                "session_id": "test", "server_git_commit": "a" * 40,
                "server_python_version": "3.11", "server_os_info": "test",
                "server_hostname": "test", "server_git_dirty": "false",
                "server_cpu_model": "test",
            }):
                with patch("run_cross_host_validation.recv_json_line", side_effect=mock_recv):
                    with patch("run_cross_host_validation.send_json_line"):
                        result = runner.run_one_experiment(
                            protocol="gmcp_r",
                            message_count=10,
                            payload_size=128,
                            repeat_id=1,
                            server_host="127.0.0.1",
                            server_port=9999,
                            client_host_id="test-client",
                            server_host_id="test-server",
                            network_path_type="loopback",
                            baseline_rtt_ms=1.0,
                            git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
                        )

        self.assertEqual(result["accepted_count"], 3)
        self.assertEqual(result["timeout_count"], 1)
        self.assertFalse(result["run_valid"])
        self.assertIn("timeout", result["failure_reason"].lower())


# ---------------------------------------------------------------------------
# 15. Aggregator: git_commit too short (V09)
# ---------------------------------------------------------------------------

class TestAggregatorV09GitCommitLength(unittest.TestCase):
    """V09: git_commit must be exactly 40 hex chars."""

    def test_short_commit_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                git_commit="short",  # invalid
                                session_id=f"commit-{proto}-{mc}-{ps}",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("git_commit length" in e for e in errors), f"Expected git_commit error, got: {errors}")


# ---------------------------------------------------------------------------
# 16. Aggregator: git_dirty=true detected (V10)
# ---------------------------------------------------------------------------

class TestAggregatorV10GitDirty(unittest.TestCase):
    """V10: git_dirty must be false for all rows."""

    def test_dirty_git_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                git_dirty="true",  # invalid
                                session_id=f"dirty-{proto}-{mc}-{ps}",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("git_dirty=true" in e for e in errors), f"Expected git_dirty error, got: {errors}")


# ---------------------------------------------------------------------------
# 17. Aggregator: configuration mismatch (V14)
# ---------------------------------------------------------------------------

class TestAggregatorV14ConfigMismatch(unittest.TestCase):
    """V14: unexpected protocol in batch must fail."""

    def test_unknown_protocol_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                # Replace gmcp_r with a fake protocol
                for proto in ["fake_proto", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                session_id=f"fake-{proto}-{mc}-{ps}",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V14" in e for e in errors), f"Expected V14 error, got: {errors}")


# ---------------------------------------------------------------------------
# 18. Aggregator: config count != 20 (V15)
# ---------------------------------------------------------------------------

class TestAggregatorV15ConfigCount(unittest.TestCase):
    """V15: each config combo must appear exactly 20 times."""

    def test_missing_combo_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                # Remove one config combo (gmcp_r, 500, 128) and add a duplicate of another
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            if proto == "gmcp_r" and mc == 500 and ps == 128:
                                continue  # skip one
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                session_id=f"cfg-{proto}-{mc}-{ps}-{rid}",
                            ))
                # Add a duplicate to keep 20 rows
                rows.append(_make_row(
                    repeat_id=1, protocol="gmcp_r", message_count=1000,
                    payload_size=512, memory_match="True",
                    session_id="cfg-dup-extra",
                ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V14" in e or "V15" in e for e in errors), f"Expected V14/V15 error, got: {errors}")


# ---------------------------------------------------------------------------
# 19. Aggregator: multiple commits (V16)
# ---------------------------------------------------------------------------

class TestAggregatorV16MultipleCommits(unittest.TestCase):
    """V16: multiple different git_commits must fail."""

    def test_two_commits_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                for j, (proto, mc, ps) in enumerate([
                    ("gmcp_r", 500, 128), ("gmcp_r", 500, 512),
                    ("gmcp_r", 1000, 128), ("gmcp_r", 1000, 512),
                    ("hash_chain", 500, 128), ("hash_chain", 500, 512),
                    ("hash_chain", 1000, 128), ("hash_chain", 1000, 512),
                    ("authenticated_hash_chain", 500, 128), ("authenticated_hash_chain", 500, 512),
                    ("authenticated_hash_chain", 1000, 128), ("authenticated_hash_chain", 1000, 512),
                    ("seq_mac", 500, 128), ("seq_mac", 500, 512),
                    ("seq_mac", 1000, 128), ("seq_mac", 1000, 512),
                    ("ticket_only", 500, 128), ("ticket_only", 500, 512),
                    ("ticket_only", 1000, 128), ("ticket_only", 1000, 512),
                ]):
                    commit = "b" * 40 if j == 0 else "a" * 40  # different commit
                    hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                    mm = "True" if proto == "gmcp_r" else ""
                    rows.append(_make_row(
                        repeat_id=1, protocol=proto, message_count=mc,
                        payload_size=ps, memory_match=mm, hash_match=hm,
                        git_commit=commit,
                        session_id=f"multi-{proto}-{mc}-{ps}",
                    ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V16" in e for e in errors), f"Expected V16 error, got: {errors}")


# ---------------------------------------------------------------------------
# 20. Runner: authenticated_hash_chain integration
# ---------------------------------------------------------------------------

class TestRunnerAuthenticatedHashChainIntegration(unittest.TestCase):
    """run_one_experiment for authenticated_hash_chain succeeds with hash_match=True."""

    @classmethod
    def setUpClass(cls):
        import run_cross_host_validation as runner
        cls._runner = runner
        cls._port = 19877
        cls._server = runner.EmbeddedTCPServer("127.0.0.1", cls._port)
        cls._server.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls._server.stop()
        time.sleep(0.1)

    def test_auth_hash_chain_integration(self):
        git_meta = {
            "git_commit": "a" * 40, "git_branch": "main",
            "git_dirty": "false", "client_cpu_model": "test",
        }
        result = self._runner.run_one_experiment(
            protocol="authenticated_hash_chain",
            message_count=3, payload_size=64, repeat_id=1,
            server_host="127.0.0.1", server_port=self._port,
            client_host_id="test-client", server_host_id="test-server",
            network_path_type="loopback", baseline_rtt_ms=0.5,
            git_meta=git_meta,
        )
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["accepted_count"], 3)
        self.assertTrue(result["hash_match"])


# ---------------------------------------------------------------------------
# 21. Aggregator: protocol-specific state mismatch (V12)
# ---------------------------------------------------------------------------

class TestAggregatorV12StateMismatch(unittest.TestCase):
    """V12: gmcp_r with memory_match=False must fail."""

    def test_memory_mismatch_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "False" if proto == "gmcp_r" else ""  # wrong!
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                session_id=f"mismatch-{proto}-{mc}-{ps}",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("memory_match=False" in e for e in errors), f"Expected memory_match error, got: {errors}")


# ---------------------------------------------------------------------------
# 22. Aggregator: hash_chain hash_match=False (V12)
# ---------------------------------------------------------------------------

class TestAggregatorV12HashMismatch(unittest.TestCase):
    """V12: hash_chain with hash_match=False must fail."""

    def test_hash_mismatch_fails(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 1:
                rows = []
                for proto in ["gmcp_r", "hash_chain", "authenticated_hash_chain", "seq_mac", "ticket_only"]:
                    for mc in [500, 1000]:
                        for ps in [128, 512]:
                            hm = "False" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                            mm = "True" if proto == "gmcp_r" else ""
                            rows.append(_make_row(
                                repeat_id=1, protocol=proto, message_count=mc,
                                payload_size=ps, memory_match=mm, hash_match=hm,
                                session_id=f"hashfail-{proto}-{mc}-{ps}",
                            ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("hash_match" in e for e in errors), f"Expected hash_match error, got: {errors}")


# ---------------------------------------------------------------------------
# 23. Runner: protocol adapter for hash_chain state tracking
# ---------------------------------------------------------------------------

class TestProtocolAdapterHashChain(unittest.TestCase):
    """ProtocolAdapter correctly tracks hash_chain state."""

    def test_hash_chain_adapter_builds_packet(self):
        adapter = ProtocolAdapter("hash_chain", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload")
        self.assertIn("chain_hash", pkt)
        self.assertIn("prev_hash", pkt)
        self.assertEqual(pkt["protocol"], "hash_chain")

    def test_hash_chain_state_match(self):
        adapter = ProtocolAdapter("hash_chain", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_hash": pkt["chain_hash"]})
        self.assertTrue(adapter.check_state_match())

    def test_hash_chain_state_mismatch(self):
        adapter = ProtocolAdapter("hash_chain", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_hash": "wrong"})
        self.assertFalse(adapter.check_state_match())


# ---------------------------------------------------------------------------
# 24. Runner: seq_mac adapter state tracking
# ---------------------------------------------------------------------------

class TestProtocolAdapterSeqMac(unittest.TestCase):
    """ProtocolAdapter correctly tracks seq_mac state (no chain)."""

    def test_seq_mac_adapter_builds_packet(self):
        adapter = ProtocolAdapter("seq_mac", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "payload")
        self.assertIn("mac", pkt)
        self.assertEqual(pkt["protocol"], "seq_mac")

    def test_seq_mac_state_match_only_needs_seq(self):
        adapter = ProtocolAdapter("seq_mac", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1})
        self.assertTrue(adapter.check_state_match())

    def test_seq_mac_mismatch_on_seq(self):
        adapter = ProtocolAdapter("seq_mac", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 99})
        self.assertFalse(adapter.check_state_match())


# ---------------------------------------------------------------------------
# 25. Runner: classify_network_path
# ---------------------------------------------------------------------------

class TestClassifyNetworkPath(unittest.TestCase):
    """classify_network_path correctly identifies loopback, LAN, and WAN."""

    def test_loopback(self):
        import run_cross_host_validation as runner
        self.assertEqual(runner.classify_network_path("127.0.0.1"), "loopback")
        self.assertEqual(runner.classify_network_path("localhost"), "loopback")

    def test_lan_10_x(self):
        import run_cross_host_validation as runner
        self.assertEqual(runner.classify_network_path("10.0.0.1"), "lan")

    def test_lan_192_168(self):
        import run_cross_host_validation as runner
        self.assertEqual(runner.classify_network_path("192.168.1.1"), "lan")

    def test_wan(self):
        import run_cross_host_validation as runner
        self.assertEqual(runner.classify_network_path("8.8.8.8"), "wan")


# ---------------------------------------------------------------------------
# 26. Runner: make_payload produces correct size
# ---------------------------------------------------------------------------

class TestMakePayload(unittest.TestCase):
    """make_payload returns payload of exactly payload_size characters."""

    def test_small_payload(self):
        import run_cross_host_validation as runner
        p = runner.make_payload(1, 10)
        self.assertEqual(len(p), 10)

    def test_large_payload(self):
        import run_cross_host_validation as runner
        p = runner.make_payload(5, 512)
        self.assertEqual(len(p), 512)
        self.assertTrue(p.startswith("cross-5-"))

    def test_exact_prefix_size(self):
        import run_cross_host_validation as runner
        prefix = "cross-1-"
        p = runner.make_payload(1, len(prefix))
        self.assertEqual(p, prefix)


# ---------------------------------------------------------------------------
# 27. Runner: HELLO rejected by server → structured failure
# ---------------------------------------------------------------------------

class TestHelloRejectedByServer(unittest.TestCase):
    """Server rejecting HELLO (ok=False) returns run_valid=False."""

    def test_hello_ok_false_returns_failure(self):
        import run_cross_host_validation as runner

        mock_sock = MagicMock()
        mock_file = MagicMock()
        with patch.object(runner, "open_tcp", return_value=(mock_sock, mock_file)):
            with patch("run_cross_host_validation.send_hello", side_effect=RuntimeError("HELLO rejected by server: auth_tag verification failed")):
                result = runner.run_one_experiment(
                    protocol="gmcp_r", message_count=5, payload_size=64,
                    repeat_id=1, server_host="127.0.0.1", server_port=9999,
                    client_host_id="c", server_host_id="s",
                    network_path_type="loopback", baseline_rtt_ms=1.0,
                    git_meta={"git_commit": "a" * 40, "git_branch": "main", "git_dirty": "false", "client_cpu_model": "test"},
                )
        self.assertFalse(result["run_valid"])
        self.assertIn("HELLO", result["failure_reason"].upper())


# ---------------------------------------------------------------------------
# 28. Runner: send_hello rejects HELLO_ACK with ok=False
# ---------------------------------------------------------------------------

class TestSendHelloRejectsNotOk(unittest.TestCase):
    """send_hello raises RuntimeError when ack['ok'] is False."""

    def test_ack_not_ok_raises(self):
        mock_sock = MagicMock()
        ack = {"ok": False, "reason": "bad auth"}
        mock_file = MagicMock()
        mock_file.readline.return_value = json.dumps(ack) + "\n"

        with self.assertRaises(RuntimeError) as ctx:
            send_hello(mock_sock, mock_file, "gmcp_r", "s1", "c1", 1)
        self.assertIn("rejected", str(ctx.exception).lower())


# ---------------------------------------------------------------------------
# 29. Runner: recv_json_line with valid nested JSON
# ---------------------------------------------------------------------------

class TestRecvJsonLineNested(unittest.TestCase):
    """recv_json_line correctly parses nested JSON structures."""

    def test_nested_json(self):
        mock_file = MagicMock()
        data = {"type": "DATA", "nested": {"a": [1, 2, 3]}, "flag": True}
        mock_file.readline.return_value = json.dumps(data) + "\n"
        result = recv_json_line(mock_file)
        self.assertEqual(result["type"], "DATA")
        self.assertEqual(result["nested"]["a"], [1, 2, 3])
        self.assertTrue(result["flag"])


# ---------------------------------------------------------------------------
# 30. Runner: ProtocolAdapter get_final_state_for_csv
# ---------------------------------------------------------------------------

class TestAdapterGetFinalStateForCsv(unittest.TestCase):
    """get_final_state_for_csv returns correct keys for each protocol."""

    def test_gmcp_r_csv_fields(self):
        adapter = ProtocolAdapter("gmcp_r", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        new_mem = update_memory(adapter.client_state["last_mem"], "s1", 1, 1, pkt["payload_hash"], "c1")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_mem": new_mem})
        fields = adapter.get_final_state_for_csv()
        self.assertIn("client_final_mem", fields)
        self.assertIn("server_final_mem", fields)
        self.assertEqual(fields["client_final_seq"], 1)

    def test_hash_chain_csv_fields(self):
        adapter = ProtocolAdapter("hash_chain", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1, "last_hash": pkt["chain_hash"]})
        fields = adapter.get_final_state_for_csv()
        self.assertIn("client_final_hash", fields)
        self.assertIn("server_final_hash", fields)

    def test_seq_mac_csv_fields(self):
        adapter = ProtocolAdapter("seq_mac", "s1", "c1", 1)
        pkt = adapter.build_packet(1, "data")
        adapter.update_after_accept(pkt, {"ok": True, "last_seq": 1})
        fields = adapter.get_final_state_for_csv()
        self.assertEqual(fields["client_final_mem"], "")
        self.assertEqual(fields["client_final_hash"], "")


# ---------------------------------------------------------------------------
# 31. Aggregator: total rows != 400 (V13)
# ---------------------------------------------------------------------------

class TestAggregatorV13TotalRows(unittest.TestCase):
    """V13: total rows across all batches must be 400."""

    def test_short_batch_redudces_total(self):
        from aggregate_cross_host_batches import validate_all
        tmpdir = tempfile.mkdtemp()
        batch_dir = Path(tmpdir) / "batches"
        batch_dir.mkdir()
        for rid in range(1, 21):
            if rid == 10:
                # Only 19 rows
                rows = []
                for j, (proto, mc, ps) in enumerate([
                    ("gmcp_r", 500, 128), ("gmcp_r", 500, 512),
                    ("gmcp_r", 1000, 128), ("gmcp_r", 1000, 512),
                    ("hash_chain", 500, 128), ("hash_chain", 500, 512),
                    ("hash_chain", 1000, 128), ("hash_chain", 1000, 512),
                    ("authenticated_hash_chain", 500, 128), ("authenticated_hash_chain", 500, 512),
                    ("authenticated_hash_chain", 1000, 128), ("authenticated_hash_chain", 1000, 512),
                    ("seq_mac", 500, 128), ("seq_mac", 500, 512),
                    ("seq_mac", 1000, 128), ("seq_mac", 1000, 512),
                    ("ticket_only", 500, 128), ("ticket_only", 500, 512),
                    ("ticket_only", 1000, 128),  # missing ticket_only 1000/512
                ]):
                    hm = "True" if proto in ("hash_chain", "authenticated_hash_chain") else ""
                    mm = "True" if proto == "gmcp_r" else ""
                    rows.append(_make_row(
                        repeat_id=10, protocol=proto, message_count=mc,
                        payload_size=ps, memory_match=mm, hash_match=hm,
                        session_id=f"v13-{proto}-{mc}-{ps}-{rid}",
                    ))
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid, rows)
            else:
                _make_batch_csv(batch_dir / f"cross_host_batch_r{rid:02d}.csv", rid)
        errors, _, _ = validate_all(batch_dir)
        self.assertTrue(any("V13" in e or "V04" in e for e in errors), f"Expected V13/V04 error, got: {errors}")


# ---------------------------------------------------------------------------
# 32. Runner: server_git_commit in result from integration
# ---------------------------------------------------------------------------

class TestRunnerServerGitCommitInResult(unittest.TestCase):
    """Integration result includes server_git_commit from HELLO_ACK."""

    @classmethod
    def setUpClass(cls):
        import run_cross_host_validation as runner
        cls._runner = runner
        cls._port = 19878
        cls._server = runner.EmbeddedTCPServer("127.0.0.1", cls._port)
        cls._server.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls._server.stop()
        time.sleep(0.1)

    def test_server_git_commit_present(self):
        git_meta = {
            "git_commit": "a" * 40, "git_branch": "main",
            "git_dirty": "false", "client_cpu_model": "test",
        }
        result = self._runner.run_one_experiment(
            protocol="gmcp_r", message_count=2, payload_size=32,
            repeat_id=1, server_host="127.0.0.1", server_port=self._port,
            client_host_id="test-client", server_host_id="test-server",
            network_path_type="loopback", baseline_rtt_ms=0.5,
            git_meta=git_meta,
        )
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(len(result.get("server_git_commit", "")), 40)
        self.assertNotEqual(result.get("server_hostname", ""), "")


if __name__ == "__main__":
    unittest.main()
