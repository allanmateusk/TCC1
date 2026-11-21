import unittest

from .incremental_metrics import compare_paired, summarize


def rows(audits, weighted=(0, 1, 1)):
    return [dict(round_index=str(i), task_id=str(i), audited=str(int(i in audits)), calibration="0",
                 consensus_correct=str(weighted[i]), majority_correct=str(int(i==2))) for i in range(3)]


class IncrementalMetricsTest(unittest.TestCase):
    def test_reports_explicit_denominators_without_seed_variance(self):
        r = summarize(rows({0}), ("0", "1", "2"))
        self.assertEqual(r["all"]["weighted_accuracy"], 2/3)
        self.assertEqual(r["non_audited"]["weighted_accuracy"], 1)
        self.assertEqual(r["non_audited"]["n"], 2)
        self.assertEqual(r["audited"]["unweighted_accuracy"], 0)
        self.assertIsNone(r["variance_between_seeds"])

    def test_same_questions_used_in_paired_non_audited_subset(self):
        r = compare_paired(rows({0}), rows({1}, (1,1,0)), ("0", "1", "2"))
        self.assertEqual(r["all"]["left"]["n"], 3)
        self.assertEqual(r["common_non_audited"]["task_ids"], ["2"])
        self.assertEqual(r["common_non_audited"]["left"]["weighted_accuracy"], 1)
        self.assertEqual(r["common_non_audited"]["right"]["weighted_accuracy"], 0)
        self.assertTrue(r["unweighted_is_readout_not_independent"])

    def test_missing_subset_is_not_reported_as_zero_accuracy(self):
        r = compare_paired(rows({0,2}), rows({1}), ("0", "1", "2"))
        self.assertIsNone(r["common_non_audited"]["right"]["weighted_accuracy"])

    def test_rejects_different_order_or_dataset(self):
        with self.assertRaises(ValueError):
            compare_paired(rows({0}), rows({1})[::-1], ("0", "1", "2"))
        with self.assertRaises(ValueError):
            summarize(rows({0}), ("0", "7", "2"))
