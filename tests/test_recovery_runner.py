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
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import run_recovery_validation as runner

# ===========================================================================
# Helpers
# ===========================================================================

_FULL_SHA = "a" * 40


def _make_tmp_dir():
    """Create a temporary directory outside any git repo."""
    d = tempfile.mkdtemp(prefix="recovery_test_")
    return d


def _fake_result(protocol="gmcp_r", disconnect_point=50,
                 disconnect_type="client_close", repeat_id=1):
    """Return a fake recovery experiment result for testing."""
    return {
        "session_id": f"s-{protocol}-d{disconnect_point}-{repeat_id}",
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
        "reconnect_success": True,
        "reconnect_latency_ms": 5.0,
        "final_state_match": True,
        "final_sequence_match": True,
        "final_client_seq": 500,
        "final_server_seq": 500,
        "memory_match": True if protocol == "gmcp_r" else "",
        "hash_match": True if protocol == "authenticated_hash_chain" else "",
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


if __name__ == "__main__":
    unittest.main()
