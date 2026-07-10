# -*- coding: utf-8 -*-
# tests/test_experiment_statistics.py
#
# Task 8: Run-Level Statistics and Concurrency
# Tests for no-SciPy calculate_statistics, calculate_observed_rate,
# and the _student_t_critical lookup table.

import math
import unittest

from gmcp.experiment_stats import (
    _student_t_critical,
    _T95,
    calculate_statistics,
    calculate_observed_rate,
    calculate_rate,
    calculate_security_metrics,
    format_statistics_for_csv,
)


class TestStudentTTable(unittest.TestCase):
    """Validate the hard-coded Student-t critical value table."""

    def test_table_covers_df_1_to_30(self):
        for df in range(1, 31):
            self.assertIn(df, _T95, f"Missing df={df}")

    def test_table_values_decrease_with_df(self):
        """t critical should decrease as df increases."""
        prev = float("inf")
        for df in range(1, 31):
            val = _T95[df]
            self.assertLess(val, prev, f"t[{df}] should be < t[{df-1}]")
            prev = val

    def test_df_1_is_12_706(self):
        self.assertAlmostEqual(_T95[1], 12.706, places=3)

    def test_df_29_is_2_045(self):
        self.assertAlmostEqual(_T95[29], 2.045, places=3)

    def test_df_30_is_2_042(self):
        self.assertAlmostEqual(_T95[30], 2.042, places=3)

    def test_large_df_uses_normal_approximation(self):
        """For df > 30, should return 1.960."""
        self.assertAlmostEqual(_student_t_critical(100), 1.960, places=3)
        self.assertAlmostEqual(_student_t_critical(1000), 1.960, places=3)

    def test_unsupported_confidence_raises(self):
        with self.assertRaises(ValueError):
            _student_t_critical(10, confidence=0.99)
        with self.assertRaises(ValueError):
            _student_t_critical(10, confidence=0.90)


class TestCalculateStatistics(unittest.TestCase):
    """Test the no-SciPy calculate_statistics function."""

    def test_empty_values(self):
        s = calculate_statistics([])
        self.assertEqual(s["n"], 0)
        self.assertEqual(s["mean"], 0.0)
        self.assertEqual(s["ci_half"], 0.0)

    def test_single_value(self):
        s = calculate_statistics([42.0])
        self.assertEqual(s["n"], 1)
        self.assertAlmostEqual(s["mean"], 42.0)
        self.assertEqual(s["std"], 0.0)
        self.assertEqual(s["ci_half"], 0.0)

    def test_known_values(self):
        """Basic sanity check with simple data."""
        s = calculate_statistics([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertEqual(s["n"], 5)
        self.assertAlmostEqual(s["mean"], 3.0)
        self.assertAlmostEqual(s["min"], 1.0)
        self.assertAlmostEqual(s["max"], 5.0)
        self.assertAlmostEqual(s["median"], 3.0)

    def test_ci_half_width_five_client(self):
        """
        Plan: "Load current 5-client run means and assert CI half-width rounds
        to 0.0896 ms."

        Construct 5 data points with mean=100.0 and std ≈ 0.072149 so that:
          t(4, 0.95) * std / sqrt(5) ≈ 0.0896 ms
        """
        # Values chosen so that sum of squared deviations = 0.020822
        # (std = sqrt(0.020822/4) ≈ 0.072149)
        target_mean = 100.0
        # deviations: [-0.1, +0.05, +0.05, -0.08, +0.08]
        # sum = 0.0, sum sq = 0.01 + 0.0025 + 0.0025 + 0.0064 + 0.0064 = 0.0278 → too big
        # Let's use: [-0.08, -0.04, 0.0, +0.04, +0.08]
        # sum sq = 0.0064 + 0.0016 + 0 + 0.0016 + 0.0064 = 0.016 → std = sqrt(0.004) ≈ 0.06325
        # ci = 2.776 * 0.06325 / 2.236 ≈ 0.0784 → not right
        #
        # We need ci ≈ 0.0896 → std = 0.0896 * sqrt(5) / 2.776 ≈ 0.07215
        # variance = 0.07215^2 ≈ 0.005206
        # sum of sq devs = 4 * 0.005206 = 0.020822
        # Choose deviations: d = [d1, d2, d3, d4, d5] with sum=0 and sum sq=0.020822
        # Try: [-a, -a/2, 0, +a/2, +a] → sum=0, sum sq = a^2 + a^2/4 + 0 + a^2/4 + a^2 = 2.5*a^2
        # 2.5*a^2 = 0.020822 → a^2 = 0.008329 → a = 0.09126
        a = math.sqrt(0.020822 / 2.5)  # ≈ 0.091263
        values = [
            target_mean - a,
            target_mean - a / 2,
            target_mean,
            target_mean + a / 2,
            target_mean + a,
        ]
        s = calculate_statistics(values)
        self.assertEqual(s["n"], 5)
        self.assertAlmostEqual(s["mean"], target_mean)
        # CI half-width should round to 0.0896
        self.assertAlmostEqual(round(s["ci_half"], 4), 0.0896, places=4)

    def test_ci_95_alias_present(self):
        """ci_95 key should be present as backward-compatible alias."""
        s = calculate_statistics([1.0, 2.0, 3.0])
        self.assertIn("ci_95", s)
        self.assertAlmostEqual(s["ci_95"], s["ci_half"])

    def test_rejects_non_95_confidence(self):
        with self.assertRaises(ValueError):
            calculate_statistics([1.0, 2.0, 3.0], confidence=0.99)


class TestCalculateObservedRate(unittest.TestCase):
    """Test the Clopper-Pearson exact boundary and Wilson interval."""

    def test_all_success_n_60(self):
        """
        Plan: "exact all-success lower bounds 94.04% for 60"
        lower = 0.025 ** (1/60) ≈ 0.9404
        """
        result = calculate_observed_rate(60, 60)
        self.assertAlmostEqual(result["rate"], 1.0)
        self.assertAlmostEqual(result["ci_lower"], 0.025 ** (1.0 / 60), places=10)
        self.assertAlmostEqual(result["ci_lower"], 0.9404, places=4)
        self.assertEqual(result["ci_upper"], 1.0)
        self.assertEqual(result["method"], "clopper_pearson_exact_boundary")

    def test_all_success_n_180(self):
        """
        Plan: "exact all-success lower bounds 97.97% for 180"
        """
        result = calculate_observed_rate(180, 180)
        self.assertAlmostEqual(result["ci_lower"], 0.025 ** (1.0 / 180), places=10)
        self.assertAlmostEqual(result["ci_lower"], 0.9797, places=4)
        self.assertEqual(result["method"], "clopper_pearson_exact_boundary")

    def test_all_success_n_900(self):
        """
        Plan: "exact all-success lower bounds 99.59% for 900"
        """
        result = calculate_observed_rate(900, 900)
        self.assertAlmostEqual(result["ci_lower"], 0.025 ** (1.0 / 900), places=10)
        self.assertAlmostEqual(result["ci_lower"], 0.9959, places=4)
        self.assertEqual(result["method"], "clopper_pearson_exact_boundary")

    def test_zero_success(self):
        """Zero success: symmetric upper bound."""
        result = calculate_observed_rate(0, 60)
        self.assertAlmostEqual(result["rate"], 0.0)
        self.assertEqual(result["ci_lower"], 0.0)
        self.assertAlmostEqual(result["ci_upper"], 1.0 - 0.025 ** (1.0 / 60), places=10)
        self.assertEqual(result["method"], "clopper_pearson_exact_boundary")

    def test_intermediate_rate_uses_wilson(self):
        """Non-extreme rates use Wilson score interval."""
        result = calculate_observed_rate(95, 100)
        self.assertAlmostEqual(result["rate"], 0.95)
        self.assertEqual(result["method"], "wilson")
        self.assertGreater(result["ci_lower"], 0.0)
        self.assertLess(result["ci_upper"], 1.0)

    def test_zero_total(self):
        result = calculate_observed_rate(0, 0)
        self.assertEqual(result["method"], "degenerate")
        self.assertEqual(result["rate"], 0.0)

    def test_exact_formula_matches_plan(self):
        """
        Verify the plan's formula:
        lower = 0.025 ** (1.0 / total_count)
        """
        for n in [10, 30, 60, 180, 500, 900]:
            result = calculate_observed_rate(n, n)
            expected = 0.025 ** (1.0 / n)
            self.assertAlmostEqual(
                result["ci_lower"], expected, places=10,
                msg=f"Failed for n={n}"
            )

    def test_success_count_and_total_count_present(self):
        result = calculate_observed_rate(95, 100)
        self.assertEqual(result["success_count"], 95)
        self.assertEqual(result["total_count"], 100)


class TestCalculateRate(unittest.TestCase):
    """Test the Wilson score calculate_rate (existing function)."""

    def test_basic(self):
        r = calculate_rate(95, 100)
        self.assertAlmostEqual(r["rate"], 0.95)
        self.assertGreater(r["ci_95_lower"], 0.0)
        self.assertLess(r["ci_95_upper"], 1.0)

    def test_zero_total(self):
        r = calculate_rate(0, 0)
        self.assertEqual(r["rate"], 0.0)


class TestSecurityMetrics(unittest.TestCase):

    def test_basic(self):
        m = calculate_security_metrics(2, 3, 100, 50)
        self.assertAlmostEqual(m["false_accept_rate"], 2 / 50)
        self.assertAlmostEqual(m["false_reject_rate"], 3 / 100)


class TestFormatStatisticsForCsv(unittest.TestCase):

    def test_prefix(self):
        row = format_statistics_for_csv([1.0, 2.0, 3.0], prefix="latency")
        self.assertIn("latency_mean", row)
        self.assertIn("latency_n", row)

    def test_no_prefix(self):
        row = format_statistics_for_csv([1.0, 2.0, 3.0])
        self.assertIn("mean", row)


class TestStatisticalAnalysisDelegation(unittest.TestCase):
    """Test that gmcp/statistical_analysis.py delegates to experiment_stats."""

    def test_calculate_confidence_interval(self):
        from gmcp.statistical_analysis import calculate_confidence_interval
        mean, lo, hi = calculate_confidence_interval([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertAlmostEqual(mean, 3.0)
        self.assertLess(lo, 3.0)
        self.assertGreater(hi, 3.0)

    def test_calculate_confidence_interval_empty(self):
        from gmcp.statistical_analysis import calculate_confidence_interval
        mean, lo, hi = calculate_confidence_interval([])
        self.assertEqual(mean, 0.0)

    def test_calculate_mean_std_ci(self):
        from gmcp.statistical_analysis import calculate_mean_std_ci
        result = calculate_mean_std_ci([1.0, 2.0, 3.0, 4.0, 5.0])
        self.assertAlmostEqual(result["mean"], 3.0)
        self.assertIn("margin_of_error", result)
        self.assertEqual(result["n"], 5)

    def test_advanced_tests_require_scipy(self):
        """t-test and ANOVA should raise RuntimeError without SciPy."""
        from gmcp.statistical_analysis import _HAS_SCIPY
        if _HAS_SCIPY:
            self.skipTest("SciPy is installed; cannot test RuntimeError path")

        from gmcp.statistical_analysis import t_test_two_samples, anova_one_way
        with self.assertRaises(RuntimeError):
            t_test_two_samples([1, 2, 3], [4, 5, 6])
        with self.assertRaises(RuntimeError):
            anova_one_way([1, 2], [3, 4])


class TestSessionRegistryLockStrategies(unittest.TestCase):
    """Verify SessionRegistry accepts both lock strategies."""

    def test_per_session_lock(self):
        from gmcp.session_registry import SessionRegistry, SessionContext
        def factory(sid, ci):
            return SessionContext(session_id=sid, state=None, verifier=None)
        reg = SessionRegistry(factory, lock_strategy="per_session_lock")
        self.assertEqual(reg.lock_strategy, "per_session_lock")

    def test_global_lock(self):
        from gmcp.session_registry import SessionRegistry, SessionContext
        def factory(sid, ci):
            return SessionContext(session_id=sid, state=None, verifier=None)
        reg = SessionRegistry(factory, lock_strategy="global_lock")
        self.assertEqual(reg.lock_strategy, "global_lock")

    def test_invalid_strategy_raises(self):
        from gmcp.session_registry import SessionRegistry, SessionContext
        def factory(sid, ci):
            return SessionContext(session_id=sid, state=None, verifier=None)
        with self.assertRaises(ValueError):
            SessionRegistry(factory, lock_strategy="bogus")


if __name__ == "__main__":
    unittest.main()
