import json
from copy import deepcopy
from pathlib import Path
import unittest

from . import campaign, incremental_campaign as inc


class IncrementalCampaignTest(unittest.TestCase):
    def setUp(self):
        self.legacy = json.loads(Path(__file__).with_name("profile.json").read_text(encoding="utf-8"))
        self.profile = inc.configure(self.legacy)
        self.rows = self.profile["scenarios"]

    def test_manifest_is_a_distinct_ordered_twenty_case_matrix(self):
        self.assertEqual(len(set(inc.IDS)), 20)
        self.assertFalse(set(inc.IDS) & set(campaign.IDS))
        self.assertEqual([sum(r["id"].startswith(f"e{i}-") for r in self.rows) for i in (4,5,6,7)], [7,7,3,3])
        self.assertEqual(list(inc.IDS), [row["id"] for row in self.rows])
        self.assertEqual([r["malicious_nodes"] for r in self.rows[:7]], [0,4,4,8,8,16,16])
        self.assertEqual([r["collusion"] for r in self.rows[:7]], [False,False,True,False,True,False,True])
        campaign.validate(self.legacy)
        self.assertEqual(self.legacy["pilot_rounds"], [5])

    def test_fixed_dates_and_random_draws_are_shared_only_within_design(self):
        for row in self.rows[:7]:
            p = inc.plan(self.profile, row, 0, 50)
            self.assertEqual(p["planned_rounds"], [10,20,30,40,50])
            self.assertEqual(p["genesis_rounds"], [])
        random_plans = [inc.plan(self.profile, row, 0, 50) for row in self.rows[7:]]
        for p in random_plans:
            self.assertEqual(p["planned_rounds"], random_plans[0]["planned_rounds"])
            self.assertEqual(p["planned_rounds"], [r for r, q in p["uniform_by_round"].items() if q < .2])
            self.assertEqual(len(p["uniform_by_round"]), 50)
        self.assertNotEqual(random_plans[0]["planned_rounds"], list(inc.FIXED))

    def test_instability_mask_is_seeded_and_independent_from_profile(self):
        masks = [inc.plan(self.profile, row, 0, 50)["simulated_absences"] for row in self.rows[-3:]]
        self.assertTrue(all(m == masks[0] for m in masks))
        marked = {i for missing in masks[0].values() for i in missing}
        self.assertEqual(len(marked), 4)
        self.assertTrue(set(range(1, 51)).issuperset(masks[0]))
        self.assertFalse(inc.plan(self.profile, self.rows[8], 0, 50)["simulated_absences"])

    def test_refuses_edits_and_wrong_seed_and_round_count(self):
        p = deepcopy(self.profile)
        p["scenarios"][0]["audit_p"] = 0
        with self.assertRaises(ValueError):
            inc.validate(p)
        with self.assertRaises(ValueError):
            inc.plan(self.profile, self.rows[0], 1, 50)
        with self.assertRaises(ValueError):
            inc.plan(self.profile, self.rows[0], 0, 5)


if __name__ == "__main__":
    unittest.main()
