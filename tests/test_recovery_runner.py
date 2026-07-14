# -*- coding: utf-8 -*-
# tests/test_recovery_runner.py
#
# Tests for run_recovery_validation.py: provenance, output protection,
# CLI validation, matrix computation, and CSV field presence.
#
# All tests target run_recovery_validation.py directly.
# Uses mocks to avoid requiring network/sudo.

import csv
import inspect
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from gmcp.config import CLIENT_ID, DATA_AUTH_KEY, EPOCH
from gmcp.crypto_utils import verify_tagged_hmac, with_hmac

import run_recovery_validation as runner

# ===========================================================================
# Helpers
# ===========================================================================

_FULL_SHA = "a" * 40

_SERVER_ENV = {
    "server_git_commit": _FULL_SHA,
    "server_python_version": "test-python",
    "server_os_info": "test-os",
    "server_hostname": "loopback-server",
    "server_git_dirty": "false",
    "server_cpu_model": "test-cpu",
}


def _make_tmp_dir():
    """Create a temporary directory outside any git repo."""
    d = tempfile.mkdtemp(prefix="recovery_test_")
    return d


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _clean_git_meta():
    return {
        "git_commit": _FULL_SHA,
        "git_branch": "test",
        "git_dirty": "false",
    }


@contextmanager
def _running_loopback_server():
    port = _free_port()
    server = runner.EmbeddedTCPServer("127.0.0.1", port)
    with patch.object(runner, "get_server_env_info", return_value=dict(_SERVER_ENV)):
        server.start()
        deadline = time.time() + 2.0
        while time.time() < deadline and not runner.ping_server("127.0.0.1", port):
            time.sleep(0.01)
        try:
            yield server, port
        finally:
            server.stop()


def _assert_port_released(testcase, port):
    deadline = time.time() + 2.0
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                time.sleep(0.01)
        except OSError:
            return
    testcase.fail(f"port {port} still accepts connections after server.stop()")


def _run_real_experiment(protocol, disconnect_type, message_count=6, disconnect_point=3):
    with _running_loopback_server() as (_, port):
        with patch.object(runner, "RECONNECT_DELAY_MS", 0):
            result = runner.run_one_recovery_experiment(
                protocol=protocol,
                message_count=message_count,
                payload_size=32,
                disconnect_point=disconnect_point,
                disconnect_type=disconnect_type,
                repeat_id=1,
                server_host="127.0.0.1",
                server_port=port,
                git_meta=_clean_git_meta(),
            )
    _assert_port_released(unittest.TestCase(), port)
    return result


def _fake_result(protocol="gmcp_r", disconnect_point=50,
                 disconnect_type="client_close", repeat_id=1):
    """Return a fake recovery experiment result for testing."""
    session_id = f"s-{protocol}-d{disconnect_point}-{disconnect_type}-{repeat_id}"
    return {
        "session_id": session_id,
        "reconnect_session_id": session_id,
        "same_session_resume": True,
        "server_resume_seq": disconnect_point,
        "resume_state_match": True,
        "resumed_from_existing_state": True,
        "experiment_type": "recovery_validation",
        "protocol": protocol,
        "message_count": 500,
        "payload_size": 128,
        "disconnect_point": disconnect_point,
        "disconnect_type": disconnect_type,
        "repeat_id": repeat_id,
        "pre_disconnect_sent": disconnect_point,
        "pre_disconnect_accepted": disconnect_point,
        "post_disconnect_sent": 500 - disconnect_point,
        "post_disconnect_accepted": 500 - disconnect_point,
        "total_sent": 500,
        "total_accepted": 500,
        "total_rejected": 0,
        "total_timeout": 0,
        "duplicate_count": 0,
        "unrecovered_count": 0,
        "server_total_received": 500,
        "server_unique_accepted": 500,
        "server_duplicate_count": 0,
        "server_rejected_count": 0,
        "missing_seq_count": 0,
        "client_server_count_match": True,
        "reconnect_success": True,
        "reconnect_latency_ms": 5.0,
        "final_state_match": True,
        "final_sequence_match": True,
        "final_client_seq": 500,
        "final_server_seq": 500,
        "memory_match": True if protocol == "gmcp_r" else "",
        "hash_match": True if protocol == "authenticated_hash_chain" else "",
        "disconnect_armed": True,
        "disconnect_triggered": True,
        "disconnect_initiator": "server" if disconnect_type == "server_close" else "client",
        "disconnect_observed": True,
        "disconnect_observed_seq": disconnect_point,
        "disconnect_boundary": "after_ack",
        "post_reconnect_first_seq": disconnect_point + 1,
        "execution_valid": True,
        "result_success": True,
        "run_valid": True,
        "failure_type": "",
        "failure_reason": "",
        "failure_timestamp": "",
        "state_auditable": True,
        "final_state_complete": True,
        "schema_version": "2",
        "client_git_commit": _FULL_SHA,
        "server_git_commit": _FULL_SHA,
        "client_git_dirty": "false",
        "server_git_dirty": "false",
        "client_hostname": "test-host",
        "server_hostname": "test-host",
        "attempt_number": 1,
        "timestamp": "2026-01-01T00:00:00+00:00",
        "elapsed_seconds": 1.0,
    }


def _fake_matrix_result(**kwargs):
    result = _fake_result(
        protocol=kwargs["protocol"],
        disconnect_point=kwargs["disconnect_point"],
        disconnect_type=kwargs["disconnect_type"],
        repeat_id=kwargs["repeat_id"],
    )
    result["message_count"] = kwargs["message_count"]
    result["payload_size"] = kwargs["payload_size"]
    result["pre_disconnect_sent"] = kwargs["disconnect_point"]
    result["pre_disconnect_accepted"] = kwargs["disconnect_point"]
    result["post_disconnect_sent"] = kwargs["message_count"] - kwargs["disconnect_point"]
    result["post_disconnect_accepted"] = kwargs["message_count"] - kwargs["disconnect_point"]
    result["total_sent"] = kwargs["message_count"]
    result["total_accepted"] = kwargs["message_count"]
    result["server_total_received"] = kwargs["message_count"]
    result["server_unique_accepted"] = kwargs["message_count"]
    result["final_client_seq"] = kwargs["message_count"]
    result["final_server_seq"] = kwargs["message_count"]
    return result


# ===========================================================================
# 1. client_git_commit为40位
# ===========================================================================

class TestClientGitCommit40Chars(unittest.TestCase):
    """Test 1: get_git_commit returns 40-char SHA."""

    def test_get_git_commit_returns_40_chars(self):
        from gmcp.experiment_transport import get_git_commit
        commit = get_git_commit()
        self.assertEqual(len(commit), 40, f"Expected 40-char SHA, got {len(commit)}: {commit}")

    def test_runner_uses_transport_get_git_commit(self):
        source = inspect.getsource(runner.main)
        self.assertIn("get_git_metadata()", source)


# ===========================================================================
# 2. server_git_commit为40位
# ===========================================================================

class TestServerGitCommit40Chars(unittest.TestCase):
    """Test 2: Server commit comes from HELLO_ACK and should be 40 chars."""

    def test_server_env_includes_git_commit(self):
        from gmcp.experiment_transport import get_server_env_info
        info = get_server_env_info()
        commit = info.get("server_git_commit", "")
        self.assertEqual(len(commit), 40, f"server_git_commit length={len(commit)}")


# ===========================================================================
# 3. --run-dir必须
# ===========================================================================

class TestRunDirRequired(unittest.TestCase):
    """Test 3: --run-dir is required."""

    def test_missing_run_dir_fails(self):
        with patch.object(sys, "argv", ["run_recovery_validation.py", "--quick"]):
            with self.assertRaises(SystemExit) as ctx:
                runner.main()
            self.assertEqual(ctx.exception.code, 2)


# ===========================================================================
# 4. 相对run-dir失败
# ===========================================================================

class TestRelativeRunDirFails(unittest.TestCase):
    """Test 4: Relative --run-dir is rejected."""

    def test_relative_run_dir_rejected(self):
        with patch.object(sys, "argv", [
            "run_recovery_validation.py", "--quick", "--run-dir", "relative/path"
        ]):
            with self.assertRaises(SystemExit) as ctx:
                runner.main()
            self.assertNotEqual(ctx.exception.code, 0)


# ===========================================================================
# 5. Git仓库内run-dir失败
# ===========================================================================

class TestGitRepoInsideRunDirFails(unittest.TestCase):
    """Test 5: --run-dir inside a git repo is rejected."""

    def test_run_dir_inside_git_repo_rejected(self):
        run_dir = _make_tmp_dir()
        try:
            git_dir = os.path.join(run_dir, ".git")
            os.makedirs(git_dir)
            with patch.object(sys, "argv", [
                "run_recovery_validation.py", "--quick", "--run-dir", run_dir
            ]):
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 6. 已存在CSV时拒绝覆盖
# ===========================================================================

class TestExistingCSVRefusesOverwrite(unittest.TestCase):
    """Test 6: --no-overwrite rejects existing output."""

    def test_no_overwrite_blocks_existing_csv(self):
        run_dir = _make_tmp_dir()
        try:
            output_csv = os.path.join(run_dir, "recovery_smoke.csv")
            with open(output_csv, "w") as f:
                f.write("existing")

            with patch.object(sys, "argv", [
                "run_recovery_validation.py", "--quick",
                "--run-dir", run_dir, "--no-overwrite"
            ]):
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 7. tmp独占创建
# ===========================================================================

class TestTmpExclusiveCreation(unittest.TestCase):
    """Test 7: Tmp file uses open(..., 'x') for exclusive creation."""

    def test_source_uses_exclusive_open(self):
        source = inspect.getsource(runner.main)
        self.assertRegex(source, r'open\(tmp_csv,\s*"x"',
                         "Should use open(tmp_csv, 'x') for exclusive creation")


# ===========================================================================
# 8. failed artifact保留
# ===========================================================================

class TestFailedArtifactPreserved(unittest.TestCase):
    """Test 8: Failed artifacts are preserved, not deleted."""

    def test_preserve_failed_artifact_moves_tmp(self):
        run_dir = _make_tmp_dir()
        try:
            tmp = os.path.join(run_dir, "result.csv.tmp")
            failed = os.path.join(run_dir, "result_attempt01.failed.csv")
            with open(tmp, "w") as f:
                f.write("data\n")

            result = runner.preserve_failed_artifact(tmp, failed)
            self.assertTrue(os.path.exists(result))
            self.assertFalse(os.path.exists(tmp))
            with open(result) as f:
                self.assertEqual(f.read(), "data\n")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_preserve_does_not_overwrite_existing_failed(self):
        run_dir = _make_tmp_dir()
        try:
            tmp = os.path.join(run_dir, "result.csv.tmp")
            failed = os.path.join(run_dir, "result.failed.csv")
            with open(tmp, "w") as f:
                f.write("new\n")
            with open(failed, "w") as f:
                f.write("old\n")

            result = runner.preserve_failed_artifact(tmp, failed)
            # Original failed preserved
            with open(failed) as f:
                self.assertEqual(f.read(), "old\n")
            # New content in conflict file
            self.assertIn("conflict", result)
            with open(result) as f:
                self.assertEqual(f.read(), "new\n")
            self.assertFalse(os.path.exists(tmp))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 9. quick矩阵行数正确
# ===========================================================================

class TestQuickMatrixRowCount(unittest.TestCase):
    """Test 9: Quick mode = 3 protocols × 2 disconnect_points × 2 types × 1 repeat = 12 rows."""

    def test_quick_matrix_calculation(self):
        protocols = runner.PROTOCOLS
        disconnect_points = runner.DISCONNECT_POINTS[:2]  # quick uses first 2
        disconnect_types = runner.DISCONNECT_TYPES
        repeats = 1
        total = len(protocols) * len(disconnect_points) * len(disconnect_types) * repeats
        self.assertEqual(len(protocols), 3)
        self.assertEqual(len(disconnect_points), 2)
        self.assertEqual(len(disconnect_types), 2)
        self.assertEqual(total, 12)


# ===========================================================================
# 10. formal矩阵行数正确
# ===========================================================================

class TestFormalMatrixRowCount(unittest.TestCase):
    """Test 10: Formal mode = 3 protocols × 3 disconnect_points × 2 types × 10 repeats = 180 rows."""

    def test_formal_matrix_calculation(self):
        protocols = runner.PROTOCOLS
        disconnect_points = runner.DISCONNECT_POINTS
        disconnect_types = runner.DISCONNECT_TYPES
        repeats = runner.REPEAT_COUNT
        total = len(protocols) * len(disconnect_points) * len(disconnect_types) * repeats
        self.assertEqual(len(protocols), 3)
        self.assertEqual(len(disconnect_points), 3)
        self.assertEqual(len(disconnect_types), 2)
        self.assertEqual(repeats, 10)
        self.assertEqual(total, 180)


# ===========================================================================
# 11. disconnect_point在结果中记录
# ===========================================================================

class TestDisconnectPointRecorded(unittest.TestCase):
    """Test 11: disconnect_point field exists in result dict."""

    def test_disconnect_point_in_result(self):
        result = _fake_result(disconnect_point=250)
        self.assertIn("disconnect_point", result)
        self.assertEqual(result["disconnect_point"], 250)

    def test_disconnect_point_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"disconnect_point"', source)


# ===========================================================================
# 12. disconnect_type在结果中记录
# ===========================================================================

class TestDisconnectTypeRecorded(unittest.TestCase):
    """Test 12: disconnect_type field exists in result dict."""

    def test_disconnect_type_in_result(self):
        result = _fake_result(disconnect_type="server_close")
        self.assertIn("disconnect_type", result)
        self.assertEqual(result["disconnect_type"], "server_close")

    def test_disconnect_type_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"disconnect_type"', source)


# ===========================================================================
# 13. duplicate_count字段存在
# ===========================================================================

class TestDuplicateCountFieldExists(unittest.TestCase):
    """Test 13: duplicate_count field exists in result."""

    def test_duplicate_count_in_result(self):
        result = _fake_result()
        self.assertIn("duplicate_count", result)

    def test_duplicate_count_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"duplicate_count"', source)


# ===========================================================================
# 14. reconnect_success字段存在
# ===========================================================================

class TestReconnectSuccessFieldExists(unittest.TestCase):
    """Test 14: reconnect_success field exists in result."""

    def test_reconnect_success_in_result(self):
        result = _fake_result()
        self.assertIn("reconnect_success", result)
        self.assertIsInstance(result["reconnect_success"], bool)

    def test_reconnect_success_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"reconnect_success"', source)


# ===========================================================================
# 15. schema_version=2
# ===========================================================================

class TestSchemaVersion2(unittest.TestCase):
    """Test 15: schema_version must be '2'."""

    def test_schema_version_constant(self):
        self.assertEqual(runner.SCHEMA_VERSION, "2")

    def test_schema_version_in_result(self):
        result = _fake_result()
        self.assertEqual(result["schema_version"], "2")

    def test_schema_version_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"schema_version"', source)


# ===========================================================================
# 16. publish_no_clobber语义
# ===========================================================================

class TestPublishNoClobber(unittest.TestCase):
    """Test 16: publish_tmp_no_clobber uses os.link + os.unlink."""

    def test_publish_success(self):
        run_dir = _make_tmp_dir()
        try:
            tmp = os.path.join(run_dir, "out.csv.tmp")
            final = os.path.join(run_dir, "out.csv")
            with open(tmp, "w") as f:
                f.write("data\n")
            runner.publish_tmp_no_clobber(tmp, final)
            self.assertTrue(os.path.exists(final))
            self.assertFalse(os.path.exists(tmp))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_publish_refuses_existing(self):
        run_dir = _make_tmp_dir()
        try:
            tmp = os.path.join(run_dir, "out.csv.tmp")
            final = os.path.join(run_dir, "out.csv")
            with open(tmp, "w") as f:
                f.write("new\n")
            with open(final, "w") as f:
                f.write("old\n")
            with self.assertRaises(FileExistsError):
                runner.publish_tmp_no_clobber(tmp, final)
            with open(final) as f:
                self.assertEqual(f.read(), "old\n")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 17. attempt_number字段
# ===========================================================================

class TestAttemptNumberField(unittest.TestCase):
    """Test 17: attempt_number field exists in CSV output."""

    def test_attempt_number_in_fieldnames(self):
        source = inspect.getsource(runner.main)
        self.assertIn('"attempt_number"', source)

    def test_attempt_number_validation(self):
        """--attempt-number 4 should fail (must be 1, 2, or 3)."""
        run_dir = _make_tmp_dir()
        try:
            with patch.object(sys, "argv", [
                "run_recovery_validation.py", "--quick",
                "--run-dir", run_dir, "--attempt-number", "4"
            ]):
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 18. EmbeddedTCPServer可实例化
# ===========================================================================

class TestEmbeddedTCPServerInstantiable(unittest.TestCase):
    """Test 18: EmbeddedTCPServer can be instantiated."""

    def test_instantiate_server(self):
        srv = runner.EmbeddedTCPServer("127.0.0.1", 0)
        self.assertEqual(srv.host, "127.0.0.1")
        self.assertEqual(srv.port, 0)

    def test_server_has_stop(self):
        srv = runner.EmbeddedTCPServer("127.0.0.1", 0)
        self.assertTrue(callable(srv.stop))


# ===========================================================================
# 19. PROTOCOLS列表包含3个协议
# ===========================================================================

class TestProtocolsList(unittest.TestCase):
    """Test 19: PROTOCOLS constant has 3 entries."""

    def test_protocols_count(self):
        self.assertEqual(len(runner.PROTOCOLS), 3)

    def test_protocols_content(self):
        self.assertIn("gmcp_r", runner.PROTOCOLS)
        self.assertIn("seq_mac", runner.PROTOCOLS)
        self.assertIn("authenticated_hash_chain", runner.PROTOCOLS)


# ===========================================================================
# 20. validate_run_dir拒绝Git仓库内路径
# ===========================================================================

class TestValidateRunDirRejectsGit(unittest.TestCase):
    """Test 20: validate_run_dir rejects paths inside git repos."""

    def test_validate_rejects_git_dir(self):
        run_dir = _make_tmp_dir()
        try:
            git_dir = os.path.join(run_dir, ".git")
            os.makedirs(git_dir)
            mock_parser = MagicMock()
            mock_parser.error = MagicMock(side_effect=SystemExit(2))

            with self.assertRaises(SystemExit):
                runner.validate_run_dir(mock_parser, run_dir)

            mock_parser.error.assert_called()
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_validate_accepts_non_git_dir(self):
        run_dir = _make_tmp_dir()
        try:
            mock_parser = MagicMock()
            result = runner.validate_run_dir(mock_parser, run_dir)
            self.assertEqual(str(result), run_dir)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestRealLoopbackSessionResume(unittest.TestCase):
    """Core recovery semantics are verified over real loopback TCP sockets."""

    def assert_same_session_resume(self, result, protocol, disconnect_type):
        self.assertTrue(result["run_valid"], result.get("failure_reason"))
        self.assertEqual(result["reconnect_session_id"], result["session_id"])
        self.assertTrue(result["same_session_resume"])
        self.assertEqual(result["server_resume_seq"], 3)
        self.assertTrue(result["resume_state_match"])
        self.assertTrue(result["resumed_from_existing_state"])
        self.assertEqual(result["post_reconnect_first_seq"], 4)
        self.assertEqual(result["server_unique_accepted"], 6)
        self.assertEqual(result["server_duplicate_count"], 0)
        self.assertEqual(result["missing_seq_count"], 0)
        self.assertTrue(result["client_server_count_match"])
        self.assertEqual(result["disconnect_initiator"],
                         "server" if disconnect_type == "server_close" else "client")
        if protocol == "gmcp_r":
            self.assertTrue(result["memory_match"])
        if protocol == "authenticated_hash_chain":
            self.assertTrue(result["hash_match"])

    def test_gmcp_client_close_resumes_same_session(self):
        self.assert_same_session_resume(
            _run_real_experiment("gmcp_r", "client_close"),
            "gmcp_r", "client_close",
        )

    def test_seq_mac_client_close_resumes_same_session(self):
        self.assert_same_session_resume(
            _run_real_experiment("seq_mac", "client_close"),
            "seq_mac", "client_close",
        )

    def test_ahc_client_close_resumes_same_session(self):
        self.assert_same_session_resume(
            _run_real_experiment("authenticated_hash_chain", "client_close"),
            "authenticated_hash_chain", "client_close",
        )

    def test_gmcp_server_close_is_server_triggered_after_ack(self):
        result = _run_real_experiment("gmcp_r", "server_close")
        self.assert_same_session_resume(result, "gmcp_r", "server_close")
        self.assertTrue(result["disconnect_armed"])
        self.assertTrue(result["disconnect_triggered"])
        self.assertTrue(result["disconnect_observed"])
        self.assertEqual(result["disconnect_observed_seq"], 3)
        self.assertEqual(result["disconnect_boundary"], "after_ack")

    def test_seq_mac_server_close_is_server_triggered_after_ack(self):
        result = _run_real_experiment("seq_mac", "server_close")
        self.assert_same_session_resume(result, "seq_mac", "server_close")
        self.assertEqual(result["disconnect_initiator"], "server")
        self.assertTrue(result["disconnect_observed"])

    def test_ahc_server_close_is_server_triggered_after_ack(self):
        result = _run_real_experiment("authenticated_hash_chain", "server_close")
        self.assert_same_session_resume(result, "authenticated_hash_chain", "server_close")
        self.assertEqual(result["disconnect_initiator"], "server")
        self.assertTrue(result["disconnect_observed"])


class TestAuthenticatedServerCounts(unittest.TestCase):
    def _open_session(self, protocol="seq_mac"):
        context = _running_loopback_server()
        server, port = context.__enter__()
        sock, file_obj = runner.open_tcp("127.0.0.1", port)
        session_id = f"count-{protocol}-{time.time_ns()}"
        runner.send_hello(sock, file_obj, protocol, session_id, CLIENT_ID, EPOCH)
        adapter = runner.ProtocolAdapter(protocol, session_id, CLIENT_ID, EPOCH)
        return context, port, sock, file_obj, session_id, adapter

    def test_duplicate_seq_increments_server_duplicate_count_once(self):
        context, port, sock, file_obj, session_id, adapter = self._open_session()
        try:
            packet = adapter.build_packet(1, "payload")
            runner.send_json_line(sock, packet)
            accepted = runner.recv_json_line(file_obj)
            self.assertTrue(accepted["ok"])
            adapter.update_after_accept(packet, accepted)

            runner.send_json_line(sock, packet)
            duplicate = runner.recv_json_line(file_obj)
            self.assertFalse(duplicate["ok"])

            final = runner.request_final_state(sock, file_obj, session_id, 1)
            self.assertEqual(final["server_total_received"], 2)
            self.assertEqual(final["server_unique_accepted"], 1)
            self.assertEqual(final["server_duplicate_count"], 1)
            self.assertEqual(final["server_rejected_count"], 1)
            self.assertEqual(final["missing_seq_count"], 0)
            self.assertTrue(verify_tagged_hmac(DATA_AUTH_KEY, final))
        finally:
            runner.close_tcp(sock, file_obj)
            context.__exit__(None, None, None)
            _assert_port_released(self, port)

    def test_missing_seq_count_comes_from_server_final_state(self):
        context, port, sock, file_obj, session_id, adapter = self._open_session()
        try:
            packet = adapter.build_packet(1, "payload")
            runner.send_json_line(sock, packet)
            accepted = runner.recv_json_line(file_obj)
            self.assertTrue(accepted["ok"])
            adapter.update_after_accept(packet, accepted)

            final = runner.request_final_state(sock, file_obj, session_id, 2)
            self.assertEqual(final["server_unique_accepted"], 1)
            self.assertEqual(final["missing_seq_count"], 1)
        finally:
            runner.close_tcp(sock, file_obj)
            context.__exit__(None, None, None)
            _assert_port_released(self, port)


class TestRecoveryModeLocking(unittest.TestCase):
    def test_quick_and_formal_are_mutually_exclusive(self):
        parser = runner.build_arg_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["--quick", "--formal"])

    def test_formal_overrides_are_rejected_before_server_start(self):
        overrides = [
            ["--protocols", "gmcp_r"],
            ["--disconnect-points", "50"],
            ["--disconnect-types", "client_close"],
            ["--repeats", "1"],
            ["--message-count", "499"],
            ["--payload-size", "127"],
        ]
        for extra in overrides:
            with self.subTest(extra=extra):
                run_dir = _make_tmp_dir()
                try:
                    argv = ["run_recovery_validation.py", "--formal", "--run-dir", run_dir, *extra]
                    with patch.object(sys, "argv", argv), \
                            patch.object(runner, "get_git_metadata", return_value=_clean_git_meta()), \
                            patch.object(runner.EmbeddedTCPServer, "start",
                                         side_effect=AssertionError("server must not start")) as start_mock:
                        with self.assertRaises(SystemExit):
                            runner.main()
                        start_mock.assert_not_called()
                finally:
                    shutil.rmtree(run_dir, ignore_errors=True)

    def test_quick_message_shape_overrides_are_rejected_before_server_start(self):
        for extra in (["--message-count", "499"], ["--payload-size", "127"]):
            with self.subTest(extra=extra):
                run_dir = _make_tmp_dir()
                try:
                    argv = ["run_recovery_validation.py", "--quick", "--run-dir", run_dir, *extra]
                    with patch.object(sys, "argv", argv), \
                            patch.object(runner, "get_git_metadata", return_value=_clean_git_meta()), \
                            patch.object(runner.EmbeddedTCPServer, "start",
                                         side_effect=AssertionError("server must not start")) as start_mock:
                        with self.assertRaises(SystemExit):
                            runner.main()
                        start_mock.assert_not_called()
                finally:
                    shutil.rmtree(run_dir, ignore_errors=True)

    def test_existing_quick_output_is_rejected_without_no_overwrite(self):
        run_dir = _make_tmp_dir()
        try:
            output = os.path.join(run_dir, "recovery_smoke.csv")
            with open(output, "w", encoding="utf-8") as f:
                f.write("existing\n")
            argv = ["run_recovery_validation.py", "--quick", "--run-dir", run_dir]
            with patch.object(sys, "argv", argv), \
                    patch.object(runner.EmbeddedTCPServer, "start",
                                 side_effect=AssertionError("server must not start")) as start_mock:
                with self.assertRaises(SystemExit):
                    runner.main()
                start_mock.assert_not_called()
            with open(output, encoding="utf-8") as f:
                self.assertEqual(f.read(), "existing\n")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_existing_formal_output_is_rejected_without_no_overwrite(self):
        run_dir = _make_tmp_dir()
        try:
            output = os.path.join(run_dir, "recovery_validation_results.csv")
            with open(output, "w", encoding="utf-8") as f:
                f.write("existing formal\n")
            argv = ["run_recovery_validation.py", "--formal", "--run-dir", run_dir]
            with patch.object(sys, "argv", argv), \
                    patch.object(runner.EmbeddedTCPServer, "start",
                                 side_effect=AssertionError("server must not start")) as start_mock:
                with self.assertRaises(SystemExit):
                    runner.main()
                start_mock.assert_not_called()
            with open(output, encoding="utf-8") as f:
                self.assertEqual(f.read(), "existing formal\n")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_existing_tmp_is_rejected_without_truncation(self):
        run_dir = _make_tmp_dir()
        try:
            tmp_output = os.path.join(run_dir, "recovery_smoke.csv.tmp")
            with open(tmp_output, "w", encoding="utf-8") as f:
                f.write("old tmp evidence\n")
            argv = ["run_recovery_validation.py", "--quick", "--run-dir", run_dir]
            with patch.object(sys, "argv", argv), \
                    patch.object(runner.EmbeddedTCPServer, "start",
                                 side_effect=AssertionError("server must not start")) as start_mock:
                with self.assertRaises(SystemExit):
                    runner.main()
                start_mock.assert_not_called()
            with open(tmp_output, encoding="utf-8") as f:
                self.assertEqual(f.read(), "old tmp evidence\n")
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


class TestRecoveryProvenanceStrict(unittest.TestCase):
    def test_non_hex_forty_character_commit_is_rejected(self):
        self.assertFalse(
            runner.provenance_is_valid("g" * 40, "g" * 40, "false", "false")
        )

    def test_matching_clean_forty_character_hex_commits_are_valid(self):
        self.assertTrue(
            runner.provenance_is_valid(_FULL_SHA, _FULL_SHA, "false", "false")
        )


class TestRecoveryPublishGate(unittest.TestCase):
    def _run_invalid_quick(self, mutate):
        run_dir = _make_tmp_dir()

        def fake_run(**kwargs):
            result = _fake_matrix_result(**kwargs)
            mutate(result)
            return result

        argv = ["run_recovery_validation.py", "--quick", "--run-dir", run_dir]
        patches = (
            patch.object(sys, "argv", argv),
            patch.object(runner, "get_git_metadata", return_value=_clean_git_meta()),
            patch.object(runner, "run_one_recovery_experiment", side_effect=fake_run),
            patch.object(runner.EmbeddedTCPServer, "start"),
            patch.object(runner.EmbeddedTCPServer, "stop"),
        )
        try:
            with patches[0], patches[1], patches[2], patches[3], patches[4]:
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
            self.assertFalse(os.path.exists(os.path.join(run_dir, "recovery_smoke.csv")))
            self.assertTrue(list(Path(run_dir).glob("*.failed.csv")))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_run_valid_false_blocks_final_csv_publish(self):
        def mutate(result):
            if result["protocol"] == "gmcp_r" and result["disconnect_point"] == 50:
                result["run_valid"] = False
                result["failure_type"] = "validation_error"
                result["failure_reason"] = "forced invalid row"

        self._run_invalid_quick(mutate)

    def test_server_commit_mismatch_blocks_publish(self):
        self._run_invalid_quick(
            lambda result: result.__setitem__("server_git_commit", "b" * 40)
        )

    def test_server_dirty_blocks_publish(self):
        self._run_invalid_quick(
            lambda result: result.__setitem__("server_git_dirty", "true")
        )


class TestRecoveryCleanupAndEndToEnd(unittest.TestCase):
    def test_exception_stops_server_releases_port_and_preserves_evidence(self):
        run_dir = _make_tmp_dir()
        port = _free_port()
        argv = [
            "run_recovery_validation.py", "--quick", "--run-dir", run_dir,
            "--port", str(port), "--message-count", "6",
        ]
        try:
            with patch.object(sys, "argv", argv), \
                    patch.object(runner, "DISCONNECT_POINTS", [2, 4]), \
                    patch.object(runner, "FIXED_MESSAGE_COUNT", 6), \
                    patch.object(runner, "get_git_metadata", return_value=_clean_git_meta()), \
                    patch.object(runner, "get_server_env_info", return_value=dict(_SERVER_ENV)), \
                    patch.object(runner, "run_one_recovery_experiment",
                                 side_effect=RuntimeError("forced runner failure")):
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
            _assert_port_released(self, port)
            self.assertFalse(os.path.exists(os.path.join(run_dir, "recovery_smoke.csv")))
            self.assertTrue(list(Path(run_dir).glob("*.failed.csv")))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_quick_real_loopback_produces_twelve_valid_unique_rows(self):
        run_dir = _make_tmp_dir()
        port = _free_port()
        argv = [
            "run_recovery_validation.py", "--quick", "--run-dir", run_dir,
            "--port", str(port), "--message-count", "6", "--payload-size", "32",
        ]
        try:
            with patch.object(sys, "argv", argv), \
                    patch.object(runner, "DISCONNECT_POINTS", [2, 4]), \
                    patch.object(runner, "FIXED_MESSAGE_COUNT", 6), \
                    patch.object(runner, "FIXED_PAYLOAD_SIZE", 32), \
                    patch.object(runner, "RECONNECT_DELAY_MS", 0), \
                    patch.object(runner, "get_git_metadata", return_value=_clean_git_meta()), \
                    patch.object(runner, "get_server_env_info", return_value=dict(_SERVER_ENV)):
                runner.main()

            output = os.path.join(run_dir, "recovery_smoke.csv")
            self.assertTrue(os.path.exists(output))
            with open(output, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 12)
            self.assertEqual(len({row["session_id"] for row in rows}), 12)
            self.assertTrue(all(row["run_valid"] == "True" for row in rows))
            self.assertTrue(all(row["same_session_resume"] == "True" for row in rows))
            _assert_port_released(self, port)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
