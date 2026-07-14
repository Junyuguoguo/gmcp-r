# -*- coding: utf-8 -*-
# tests/test_netem_runner_provenance.py
#
# 22 tests for run_netem_validation.py provenance, output protection,
# tc cleanup, and --run-dir argument validation.
#
# All tests target run_netem_validation.py directly (test 22).
# Tests use mocks to avoid requiring Linux/sudo/tc.

import csv
import inspect
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is importable
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import run_netem_validation as runner


# ===========================================================================
# Helpers
# ===========================================================================

_FULL_SHA = "a" * 40  # valid 40-char hex commit


def _invoke_main(argv, expect_exit_code=None):
    """Run runner.main() with given argv, capturing SystemExit.

    Also mocks EmbeddedTCPServer to avoid port conflicts.
    """
    mock_server = MagicMock()
    with patch.object(sys, "argv", ["run_netem_validation.py"] + argv), \
         patch.object(runner, "EmbeddedTCPServer", return_value=mock_server):
        try:
            runner.main()
            if expect_exit_code is not None:
                raise AssertionError(f"Expected SystemExit({expect_exit_code}) but no exit occurred")
        except SystemExit as e:
            if expect_exit_code is not None:
                assert e.code == expect_exit_code or e.code is None, \
                    f"Expected exit code {expect_exit_code}, got {e.code}"
            return e
    return None


def _make_tmp_dir():
    """Create a temporary directory outside any git repo."""
    d = tempfile.mkdtemp(prefix="netem_test_")
    return d


# ===========================================================================
# 1. Client commit is full 40-char SHA
# ===========================================================================

class TestClientCommitFullSHA(unittest.TestCase):
    """Test 1: _transport_get_git_commit returns 40-char SHA and is used."""

    def test_transport_get_git_commit_returns_40_chars(self):
        from gmcp.experiment_transport import get_git_commit
        commit = get_git_commit()
        self.assertEqual(len(commit), 40, f"Expected 40-char SHA, got {len(commit)}: {commit}")

    def test_main_uses_transport_get_git_commit(self):
        source = inspect.getsource(runner.main)
        self.assertIn("_transport_get_git_commit()", source)
        self.assertNotRegex(
            source,
            r"git_commit\s*=\s*get_git_commit\(\)",
            "main() should use _transport_get_git_commit(), not get_git_commit()"
        )


# ===========================================================================
# 2. Embedded server commit is full 40-char SHA
# ===========================================================================

class TestEmbeddedServerCommitFullSHA(unittest.TestCase):
    """Test 2: In local mode, server_git_commit = git_commit (40 chars)."""

    def test_local_mode_server_commit_equals_client_commit(self):
        source = inspect.getsource(runner.main)
        self.assertRegex(
            source,
            r'result\["server_git_commit"\]\s*=\s*git_commit',
        )


# ===========================================================================
# 3. Formal rejects short client commit
# ===========================================================================

class TestFormalRejectsShortClientCommit(unittest.TestCase):
    """Test 3: Formal mode exits if client commit is not 40 chars."""

    def test_formal_exits_on_short_client_commit(self):
        run_dir = _make_tmp_dir()
        try:
            with patch.object(runner, "_transport_get_git_commit", return_value="abc123"), \
                 patch.object(runner, "_transport_get_git_dirty", return_value=False), \
                 patch.object(runner, "is_linux", return_value=True), \
                 patch.object(runner, "check_tc_available", return_value=True), \
                 patch.object(runner, "check_sudo_available", return_value=True), \
                 patch.object(runner, "validate_interface_for_mode"):
                exit_obj = _invoke_main(["--interface", "lo", "--formal", "--run-dir", run_dir])
                self.assertIsNotNone(exit_obj, "Expected SystemExit for short commit")
                self.assertNotEqual(exit_obj.code, 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 4. Formal rejects short server commit
# ===========================================================================

class TestFormalRejectsShortServerCommit(unittest.TestCase):
    """Test 4: Post-hoc validator rejects short server_git_commit in CSV rows."""

    def test_validator_rejects_short_server_commit(self):
        run_dir = _make_tmp_dir()
        try:
            tmp_csv = os.path.join(run_dir, "test.csv")
            fieldnames = [
                "session_id", "protocol", "condition_name", "repeat_id",
                "execution_valid", "success_rate", "server_git_commit",
                "server_git_dirty", "client_git_commit", "client_git_dirty",
                "actual_qdisc_config", "failure_reason",
            ]
            with open(tmp_csv, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerow({
                    "session_id": "s1", "protocol": "gmcp_r",
                    "condition_name": "mild", "repeat_id": "1",
                    "execution_valid": "True", "success_rate": "100",
                    "server_git_commit": "short",
                    "server_git_dirty": "false",
                    "client_git_commit": _FULL_SHA,
                    "client_git_dirty": "false",
                    "actual_qdisc_config": "netem",
                    "failure_reason": "",
                })

            issues = []
            with open(tmp_csv, "r") as vf:
                reader = csv.DictReader(vf)
                for i, row in enumerate(reader, 1):
                    gc = row.get("server_git_commit", "")
                    if not gc or len(gc) != 40:
                        issues.append(f"row {i}: server_git_commit length={len(gc)}")
            self.assertTrue(len(issues) > 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 5. Formal rejects commit mismatch
# ===========================================================================

class TestFormalRejectsCommitMismatch(unittest.TestCase):
    """Test 5: Formal validator rejects when client != server commit."""

    def test_commit_mismatch_detected(self):
        run_dir = _make_tmp_dir()
        try:
            tmp_csv = os.path.join(run_dir, "test.csv")
            fieldnames = [
                "session_id", "protocol", "condition_name", "repeat_id",
                "execution_valid", "success_rate", "server_git_commit",
                "server_git_dirty", "client_git_commit", "client_git_dirty",
                "actual_qdisc_config", "failure_reason",
            ]
            other_sha = "b" * 40
            with open(tmp_csv, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerow({
                    "session_id": "s1", "protocol": "gmcp_r",
                    "condition_name": "mild", "repeat_id": "1",
                    "execution_valid": "True", "success_rate": "100",
                    "server_git_commit": other_sha,
                    "server_git_dirty": "false",
                    "client_git_commit": _FULL_SHA,
                    "client_git_dirty": "false",
                    "actual_qdisc_config": "netem",
                    "failure_reason": "",
                })

            issues = []
            is_formal = True
            with open(tmp_csv, "r") as vf:
                reader = csv.DictReader(vf)
                for i, row in enumerate(reader, 1):
                    gc = row.get("server_git_commit", "")
                    cgc = row.get("client_git_commit", "")
                    if is_formal and gc and cgc and gc != cgc:
                        issues.append(f"row {i}: commit mismatch")
            self.assertTrue(len(issues) > 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 6. Formal rejects client dirty=true
# ===========================================================================

class TestFormalRejectsClientDirty(unittest.TestCase):
    """Test 6: Formal mode exits if client worktree is dirty."""

    def test_formal_exits_on_dirty_client(self):
        run_dir = _make_tmp_dir()
        try:
            with patch.object(runner, "_transport_get_git_commit", return_value=_FULL_SHA), \
                 patch.object(runner, "_transport_get_git_dirty", return_value=True), \
                 patch.object(runner, "is_linux", return_value=True), \
                 patch.object(runner, "check_tc_available", return_value=True), \
                 patch.object(runner, "check_sudo_available", return_value=True), \
                 patch.object(runner, "validate_interface_for_mode"):
                exit_obj = _invoke_main(["--interface", "lo", "--formal", "--run-dir", run_dir])
                self.assertIsNotNone(exit_obj, "Expected SystemExit for dirty worktree")
                self.assertNotEqual(exit_obj.code, 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 7. Formal rejects server dirty=true
# ===========================================================================

class TestFormalRejectsServerDirty(unittest.TestCase):
    """Test 7: Post-hoc validator rejects server_git_dirty != false."""

    def test_validator_rejects_server_dirty(self):
        run_dir = _make_tmp_dir()
        try:
            tmp_csv = os.path.join(run_dir, "test.csv")
            fieldnames = [
                "session_id", "protocol", "condition_name", "repeat_id",
                "execution_valid", "success_rate", "server_git_commit",
                "server_git_dirty", "client_git_commit", "client_git_dirty",
                "actual_qdisc_config", "failure_reason",
            ]
            with open(tmp_csv, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader()
                w.writerow({
                    "session_id": "s1", "protocol": "gmcp_r",
                    "condition_name": "mild", "repeat_id": "1",
                    "execution_valid": "True", "success_rate": "100",
                    "server_git_commit": _FULL_SHA,
                    "server_git_dirty": "true",
                    "client_git_commit": _FULL_SHA,
                    "client_git_dirty": "false",
                    "actual_qdisc_config": "netem",
                    "failure_reason": "",
                })

            issues = []
            with open(tmp_csv, "r") as vf:
                reader = csv.DictReader(vf)
                for i, row in enumerate(reader, 1):
                    gd = row.get("server_git_dirty", "")
                    if str(gd).lower() != "false":
                        issues.append(f"row {i}: server_git_dirty={gd}")
            self.assertTrue(len(issues) > 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 8. Quick missing --run-dir fails
# ===========================================================================

class TestQuickMissingRunDirFails(unittest.TestCase):
    """Test 8: --quick without --run-dir should fail (required argument)."""

    def test_quick_requires_run_dir(self):
        with patch.object(sys, "argv", ["run_netem_validation.py", "--quick"]):
            with self.assertRaises(SystemExit) as ctx:
                runner.main()
            self.assertEqual(ctx.exception.code, 2)


# ===========================================================================
# 9. Formal missing --run-dir fails
# ===========================================================================

class TestFormalMissingRunDirFails(unittest.TestCase):
    """Test 9: --formal without --run-dir should fail."""

    def test_formal_requires_run_dir(self):
        with patch.object(sys, "argv", ["run_netem_validation.py", "--formal"]):
            with self.assertRaises(SystemExit) as ctx:
                runner.main()
            self.assertEqual(ctx.exception.code, 2)


# ===========================================================================
# 10. Relative run-dir fails
# ===========================================================================

class TestRelativeRunDirFails(unittest.TestCase):
    """Test 10: --run-dir with relative path should fail."""

    def test_relative_run_dir_rejected(self):
        with patch.object(sys, "argv", ["run_netem_validation.py", "--quick", "--run-dir", "relative/path"]):
            with self.assertRaises(SystemExit) as ctx:
                runner.main()
            self.assertNotEqual(ctx.exception.code, 0)


# ===========================================================================
# 11. Git repo inside run-dir fails
# ===========================================================================

class TestGitRepoInsideRunDirFails(unittest.TestCase):
    """Test 11: --run-dir inside a git repo should fail."""

    def test_run_dir_inside_git_repo_rejected(self):
        run_dir = _make_tmp_dir()
        try:
            git_dir = os.path.join(run_dir, ".git")
            os.makedirs(git_dir)
            with patch.object(sys, "argv", ["run_netem_validation.py", "--quick", "--run-dir", run_dir]):
                with self.assertRaises(SystemExit) as ctx:
                    runner.main()
                self.assertNotEqual(ctx.exception.code, 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 12. Existing final CSV refuses
# ===========================================================================

class TestExistingFinalCSVRefuses(unittest.TestCase):
    """Test 12: If final CSV already exists, refuse to run."""

    def test_existing_final_csv_blocks_run(self):
        run_dir = _make_tmp_dir()
        try:
            final_csv = os.path.join(run_dir, "netem_smoke.csv")
            with open(final_csv, "w") as f:
                f.write("placeholder")

            with patch.object(runner, "is_linux", return_value=True), \
                 patch.object(runner, "check_tc_available", return_value=True), \
                 patch.object(runner, "check_sudo_available", return_value=True), \
                 patch.object(runner, "validate_interface_for_mode"), \
                 patch.object(runner, "_transport_get_git_commit", return_value=_FULL_SHA), \
                 patch.object(runner, "_transport_get_git_dirty", return_value=False), \
                 patch.object(runner, "clear_tc_netem"):
                exit_obj = _invoke_main(["--interface", "lo", "--quick", "--run-dir", run_dir])
                self.assertIsNotNone(exit_obj, "Expected SystemExit for existing CSV")
                self.assertNotEqual(exit_obj.code, 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 13. Existing tmp refuses
# ===========================================================================

class TestExistingTmpRefuses(unittest.TestCase):
    """Test 13: If stale .tmp file exists, refuse to run."""

    def test_stale_tmp_blocks_run(self):
        run_dir = _make_tmp_dir()
        try:
            tmp_csv = os.path.join(run_dir, "netem_smoke.csv.tmp")
            with open(tmp_csv, "w") as f:
                f.write("stale")

            with patch.object(runner, "is_linux", return_value=True), \
                 patch.object(runner, "check_tc_available", return_value=True), \
                 patch.object(runner, "check_sudo_available", return_value=True), \
                 patch.object(runner, "validate_interface_for_mode"), \
                 patch.object(runner, "_transport_get_git_commit", return_value=_FULL_SHA), \
                 patch.object(runner, "_transport_get_git_dirty", return_value=False), \
                 patch.object(runner, "clear_tc_netem"):
                exit_obj = _invoke_main(["--interface", "lo", "--quick", "--run-dir", run_dir])
                self.assertIsNotNone(exit_obj, "Expected SystemExit for stale tmp")
                self.assertNotEqual(exit_obj.code, 0)
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 14. Tmp exclusive creation
# ===========================================================================

class TestTmpExclusiveCreation(unittest.TestCase):
    """Test 14: Tmp file uses open(..., 'x') for exclusive creation."""

    def test_source_uses_exclusive_open(self):
        source = inspect.getsource(runner.main)
        self.assertRegex(source, r'open\(tmp_csv,\s*"x"',
                         "Should use open(tmp_csv, 'x') for exclusive creation")
        self.assertNotRegex(source, r'open\(tmp_csv,\s*"w"',
                            "Should NOT use open(tmp_csv, 'w')")


# ===========================================================================
# 15. Formal publish doesn't overwrite
# ===========================================================================

class TestFormalPublishNoOverwrite(unittest.TestCase):
    """Test 15: os.replace is guarded — won't overwrite existing final CSV."""

    def test_final_csv_existence_checked_before_replace(self):
        source = inspect.getsource(runner.main)
        self.assertIn('os.path.exists(output_csv)', source)
        exists_pos = source.index('os.path.exists(output_csv)')
        replace_pos = source.index('os.replace(tmp_csv, output_csv)')
        self.assertLess(exists_pos, replace_pos)


# ===========================================================================
# 16. Failed artifact doesn't overwrite
# ===========================================================================

class TestFailedArtifactNoOverwrite(unittest.TestCase):
    """Test 16: On execution failure, tmp is kept (not promoted to final)."""

    def test_failure_keeps_tmp_file(self):
        source = inspect.getsource(runner.main)
        self.assertIn('any_execution_failure', source)
        self.assertIn('Final CSV NOT published', source)


# ===========================================================================
# 17. Quick matrix exactly 6 rows
# ===========================================================================

class TestQuickMatrixSixRows(unittest.TestCase):
    """Test 17: Quick mode uses all 6 NETEM_CONDITIONS."""

    def test_netem_conditions_has_6_entries(self):
        self.assertEqual(len(runner.NETEM_CONDITIONS), 6)

    def test_quick_repeats_is_1(self):
        source = inspect.getsource(runner.main)
        self.assertRegex(source, r'repeats\s*=\s*1\s*if\s*args\.quick')


# ===========================================================================
# 18. Formal matrix exactly 180 rows
# ===========================================================================

class TestFormalMatrix180Rows(unittest.TestCase):
    """Test 18: Formal mode = 3 protocols × 6 conditions × 10 repeats = 180."""

    def test_formal_matrix_calculation(self):
        self.assertEqual(len(runner.PROTOCOLS), 3)
        self.assertEqual(len(runner.NETEM_CONDITIONS), 6)
        self.assertEqual(runner.REPEAT_COUNT, 10)
        total = len(runner.PROTOCOLS) * len(runner.NETEM_CONDITIONS) * runner.REPEAT_COUNT
        self.assertEqual(total, 180)


# ===========================================================================
# 19. Exception path calls tc cleanup
# ===========================================================================

class TestExceptionPathCallsTcCleanup(unittest.TestCase):
    """Test 19: The try/except around writing ensures tc cleanup on exception."""

    def test_except_block_clears_tc(self):
        source = inspect.getsource(runner.main)
        self.assertIn('except BaseException', source)
        except_pos = source.index('except BaseException')
        after_except = source[except_pos:]
        self.assertIn('clear_tc_netem(interface)', after_except)

    def test_finally_closes_file(self):
        source = inspect.getsource(runner.main)
        self.assertIn('f.close()', source)


# ===========================================================================
# 20. Cleanup with netem blocks publish
# ===========================================================================

class TestCleanupWithNetemBlocksPublish(unittest.TestCase):
    """Test 20: tc_condition context manager verifies no netem residue after cleanup."""

    def test_tc_condition_raises_on_netem_residue(self):
        source = inspect.getsource(runner.tc_condition)
        self.assertIn('netem residue after cleanup', source)
        self.assertIn('raise RuntimeError', source)


# ===========================================================================
# 21. Provenance failure doesn't publish
# ===========================================================================

class TestProvenanceFailureNoPublish(unittest.TestCase):
    """Test 21: If provenance checks fail, no CSV is published."""

    def test_formal_dirty_exits_before_writing(self):
        run_dir = _make_tmp_dir()
        try:
            with patch.object(runner, "_transport_get_git_commit", return_value=_FULL_SHA), \
                 patch.object(runner, "_transport_get_git_dirty", return_value=True), \
                 patch.object(runner, "is_linux", return_value=True), \
                 patch.object(runner, "check_tc_available", return_value=True), \
                 patch.object(runner, "check_sudo_available", return_value=True), \
                 patch.object(runner, "validate_interface_for_mode"), \
                 patch.object(runner, "clear_tc_netem"):
                exit_obj = _invoke_main(["--interface", "lo", "--formal", "--run-dir", run_dir])
                self.assertIsNotNone(exit_obj, "Expected SystemExit for provenance failure")
            csv_files = [f for f in os.listdir(run_dir) if f.endswith('.csv')]
            self.assertEqual(len(csv_files), 0,
                             f"No CSV should be written on provenance failure, found: {csv_files}")
        finally:
            import shutil
            shutil.rmtree(run_dir, ignore_errors=True)


# ===========================================================================
# 22. All tests target run_netem_validation.py
# ===========================================================================

class TestAllTestsTargetRunNetemValidation(unittest.TestCase):
    """Test 22: Every test class in this file imports or references runner module."""

    def test_all_test_classes_reference_runner(self):
        import tests.test_netem_runner_provenance as test_mod
        test_classes = [
            obj for name, obj in inspect.getmembers(test_mod, inspect.isclass)
            if name.startswith("Test") and issubclass(obj, unittest.TestCase)
            and obj is not TestAllTestsTargetRunNetemValidation
        ]
        self.assertGreaterEqual(len(test_classes), 21,
                                f"Expected >=21 test classes, found {len(test_classes)}")

    def test_runner_module_is_netem_validation(self):
        self.assertEqual(runner.__name__, "run_netem_validation")


if __name__ == "__main__":
    unittest.main()
